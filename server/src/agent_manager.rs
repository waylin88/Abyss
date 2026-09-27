use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::crypto::XorCipher;
use crate::ip_lookup::IpLookup;

/// Ban an IP after this many failed handshakes within `BAN_WINDOW`.
const BAN_FAILURE_THRESHOLD: usize = 3;
/// Time window (seconds) for counting handshake failures.
const BAN_WINDOW_SECS: u64 = 60;
/// How long an IP stays banned (seconds).
const BAN_DURATION_SECS: u64 = 300;
/// Max time (seconds) to wait for the HELLO handshake before dropping.
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Set TCP keepalive so a dead connection (kill -9, power loss) is
/// detected within ~12 minutes rather than the OS default of 2 hours.
/// The 30-minute application heartbeat catches any remaining cases.
fn set_tcp_keepalive(s: &TcpStream) {
    use socket2::{SockRef, TcpKeepalive};
    let sock_ref = SockRef::from(s);
    let keepalive = TcpKeepalive::new().with_time(Duration::from_secs(30));
    let _ = sock_ref.set_tcp_keepalive(&keepalive);
}

pub struct AgentManager {
    /// token → id → AgentHandle
    agents: Mutex<HashMap<String, HashMap<String, AgentHandle>>>,
    /// Recently disconnected agents (for offline list display)
    offline_agents: Mutex<Vec<AgentInfo>>,
    next_id: AtomicU64,
    tunnels: Mutex<HashMap<String, TunnelHandle>>,
    pending_results: Mutex<HashMap<String, mpsc::Sender<ExecResult>>>,
    forwards: Mutex<HashMap<String, ForwardHandle>>,
    /// Manual ping awaits — keyed by agent_id
    pending_pings: Mutex<HashMap<String, oneshot::Sender<bool>>>,
    /// IP geolocation lookup (纯真IP库)
    ip_lookup: IpLookup,
    /// Currently selected web proxy agent (only this agent's web UI is accessible via proxy)
    web_agent: Mutex<Option<String>>,
    /// IPs currently banned (IP → ban expiry instant)
    banned_ips: Mutex<HashMap<String, Instant>>,
    /// Handshake failure history per IP (for automatic banning)
    ban_failures: Mutex<HashMap<String, Vec<Instant>>>,
}

pub struct AgentHandle {
    pub name: String,
    pub addr: SocketAddr,
    pub connected_at: std::time::Instant,
    pub tx: mpsc::Sender<Vec<u8>>,
    pub ip_location: String,
}

pub struct TunnelHandle {
    pub agent_id: String,
    pub client: Option<tokio::net::tcp::OwnedWriteHalf>,
}

#[derive(Clone)]
pub struct ExecResult {
    pub code: i32,
    pub output: String,
}

pub struct ForwardHandle {
    pub agent_id: String,
    pub agent_name: String,
    pub local_addr: String,
    pub server_port: u16,
    pub stop_tx: tokio::sync::oneshot::Sender<()>,
}

#[derive(serde::Serialize, Clone)]
pub struct ForwardInfo {
    pub id: String,
    pub agent_id: String,
    pub agent_name: String,
    pub local_addr: String,
    pub server_port: u16,
}

#[derive(serde::Serialize, Clone)]
pub struct ForwardConflict {
    pub forward_id: String,
    pub agent_id: String,
    pub agent_name: String,
    pub local_addr: String,
}

impl AgentManager {
    pub fn new(ip_lookup: IpLookup) -> Self {
        Self {
            agents: Mutex::new(HashMap::new()),
            offline_agents: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
            tunnels: Mutex::new(HashMap::new()),
            pending_results: Mutex::new(HashMap::new()),
            forwards: Mutex::new(HashMap::new()),
            pending_pings: Mutex::new(HashMap::new()),
            ip_lookup,
            web_agent: Mutex::new(None),
            banned_ips: Mutex::new(HashMap::new()),
            ban_failures: Mutex::new(HashMap::new()),
        }
    }

    /// Set the currently selected web proxy agent.
    /// Only this agent's port 80 will be accessible via the HTTP proxy.
    pub async fn set_web_agent(&self, agent_id: &str) {
        let mut w = self.web_agent.lock().await;
        *w = Some(agent_id.to_string());
    }

    /// Clear the web agent restriction (allow all).
    pub async fn clear_web_agent(&self) {
        let mut w = self.web_agent.lock().await;
        *w = None;
    }

    /// Check if a given agent_id is the currently selected web agent.
    pub async fn check_web_agent(&self, agent_id: &str) -> bool {
        let w = self.web_agent.lock().await;
        match w.as_ref() {
            Some(allowed) => agent_id == allowed.as_str(),
            None => false, // no agent selected → deny all proxy access
        }
    }

    // ── IP banning ────────────────────────────────────────────────

    /// Check if an IP is currently banned.
    pub async fn is_ip_banned(&self, ip: &str) -> bool {
        let bans = self.banned_ips.lock().await;
        if let Some(expires) = bans.get(ip) {
            if *expires > Instant::now() {
                return true;
            }
        }
        false
    }

    /// Record a failed handshake from `ip`. Returns `true` if the IP
    /// should now be banned (threshold reached).
    pub async fn record_handshake_failure(&self, ip: &str) -> bool {
        let now = Instant::now();
        // Clean expired failures and add current
        let mut failures = self.ban_failures.lock().await;
        let entry = failures.entry(ip.to_string()).or_insert_with(Vec::new);
        entry.retain(|t| now.duration_since(*t).as_secs() < BAN_WINDOW_SECS);
        entry.push(now);
        entry.len() >= BAN_FAILURE_THRESHOLD
    }

    /// Ban an IP for the configured duration.
    pub async fn ban_ip(&self, ip: &str) {
        let mut bans = self.banned_ips.lock().await;
        let expiry = Instant::now() + Duration::from_secs(BAN_DURATION_SECS);
        bans.insert(ip.to_string(), expiry);
        println!(
            "[server] 🚫 banned {} for {}s (handshake flood)",
            ip, BAN_DURATION_SECS
        );
        // Clean up failure history for this IP
        let mut failures = self.ban_failures.lock().await;
        failures.remove(ip);
    }

    /// Periodically clean up expired bans (call from background task).
    pub async fn cleanup_bans(&self) {
        let mut bans = self.banned_ips.lock().await;
        let now = Instant::now();
        bans.retain(|_, expires| *expires > now);
    }

    /// Get the effective agent_id by prefixing with token for isolation.
    /// When token is non-empty: "{token}:{id}", otherwise just "{id}".
    pub fn qualified_id(token: &str, id: &str) -> String {
        if token.is_empty() {
            id.to_string()
        } else {
            format!("{}:{}", token, id)
        }
    }

    pub async fn list(&self) -> Vec<AgentInfo> {
        let agents = self.agents.lock().await;
        let mut result = Vec::new();
        for (token, group) in agents.iter() {
            for (k, v) in group.iter() {
                result.push(AgentInfo {
                    id: k.clone(),
                    name: v.name.clone(),
                    addr: v.addr.to_string(),
                    uptime_secs: v.connected_at.elapsed().as_secs(),
                    token: token.clone(),
                    online: true,
                    last_seen: 0,
                    connected_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        - v.connected_at.elapsed().as_secs(),
                    ip_location: v.ip_location.clone(),
                });
            }
        }
        result
    }

    /// Return all agents (online + offline), optionally filtered by query string.
    /// `query` matches against agent id or name (case-insensitive).
    pub async fn list_all(&self, query: &str) -> Vec<AgentInfo> {
        let online = self.list().await;
        let offline = self.offline_agents.lock().await;

        let query = query.trim().to_lowercase();
        let matches = |info: &AgentInfo| -> bool {
            if query.is_empty() {
                return true;
            }
            info.id.to_lowercase().contains(&query)
                || info.name.to_lowercase().contains(&query)
                || info.addr.to_lowercase().contains(&query)
        };

        let mut result: Vec<AgentInfo> = online.into_iter().filter(|a| matches(a)).collect();
        // Collect online IDs into owned strings to avoid borrow conflict
        let online_ids: std::collections::HashSet<String> =
            result.iter().map(|a| a.id.clone()).collect();
        for a in offline.iter() {
            if matches(a) && !online_ids.contains(&a.id) {
                result.push(a.clone());
            }
        }
        result
    }

    /// Save a disconnected agent to the offline history list.
    pub async fn add_offline(&self, info: AgentInfo) {
        let mut offline = self.offline_agents.lock().await;
        // Remove previous record of the same agent
        offline.retain(|a| a.id != info.id || a.token != info.token);
        // Insert at the front (most recent first)
        offline.insert(0, info);
        // Cap at 200 entries to avoid unbounded memory
        offline.truncate(200);
    }

    pub async fn list_forwards(&self) -> Vec<ForwardInfo> {
        let forwards = self.forwards.lock().await;
        forwards
            .iter()
            .map(|(id, h)| ForwardInfo {
                id: id.clone(),
                agent_id: h.agent_id.clone(),
                agent_name: h.agent_name.clone(),
                local_addr: h.local_addr.clone(),
                server_port: h.server_port,
            })
            .collect()
    }

    pub async fn send_to_agent(&self, agent_id: &str, data: Vec<u8>) -> anyhow::Result<()> {
        let agents = self.agents.lock().await;
        for (_token, group) in agents.iter() {
            if let Some(handle) = group.get(agent_id) {
                handle.tx.send(data).await?;
                return Ok(());
            }
        }
        Err(anyhow::anyhow!("agent not found: {}", agent_id))
    }

    pub async fn exec(&self, agent_id: &str, cmd: &str) -> anyhow::Result<ExecResult> {
        let (tx, mut rx) = mpsc::channel::<ExecResult>(1);
        let op_id = self.next_id.fetch_add(1, Ordering::Relaxed).to_string();

        let msg = format!("EXEC {} {}\n", op_id, cmd).into_bytes();
        self.send_to_agent(agent_id, msg).await?;

        {
            let mut pending = self.pending_results.lock().await;
            pending.insert(op_id.clone(), tx);
        }

        match tokio::time::timeout(std::time::Duration::from_secs(30), rx.recv()).await {
            Ok(Some(result)) => Ok(result),
            Ok(None) => Err(anyhow::anyhow!("agent disconnected before result")),
            Err(_) => {
                self.pending_results.lock().await.remove(&op_id);
                Err(anyhow::anyhow!("exec timeout"))
            }
        }
    }

    pub async fn forward(
        self: &Arc<Self>,
        agent_id: &str,
        agent_name: &str,
        local_addr: &str,
        server_port: u16,
        force: bool,
    ) -> anyhow::Result<()> {
        // Check if port is already occupied by another forward
        let conflict = {
            let forwards = self.forwards.lock().await;
            forwards
                .iter()
                .find(|(_, h)| h.server_port == server_port)
                .map(|(id, h)| ForwardConflict {
                    forward_id: id.clone(),
                    agent_id: h.agent_id.clone(),
                    agent_name: h.agent_name.clone(),
                    local_addr: h.local_addr.clone(),
                })
        };

        if let Some(c) = conflict {
            if !force {
                return Err(anyhow::anyhow!(
                    "PORT_CONFLICT:{}:{}:{}:{}",
                    c.forward_id,
                    c.agent_id,
                    c.agent_name,
                    c.local_addr
                ));
            }
            // Stop the conflicting forward first
            self.stop_forward(&c.forward_id).await?;
            // Give the OS a moment to release the port
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        start_port_forward(
            Arc::clone(self),
            agent_id.to_string(),
            agent_name.to_string(),
            local_addr.to_string(),
            server_port,
        )
        .await
    }

    pub async fn stop_forward(&self, forward_id: &str) -> anyhow::Result<()> {
        let mut forwards = self.forwards.lock().await;
        if let Some(handle) = forwards.remove(forward_id) {
            let _ = handle.stop_tx.send(());
            println!("[server] forward {} stopped", forward_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("forward not found: {}", forward_id))
        }
    }

    pub async fn stop_all_forwards_for_agent(&self, agent_id: &str) {
        let mut forwards = self.forwards.lock().await;
        let to_stop: Vec<String> = forwards
            .iter()
            .filter(|(_, h)| h.agent_id == agent_id)
            .map(|(id, _)| id.clone())
            .collect();
        for id in to_stop {
            if let Some(handle) = forwards.remove(&id) {
                let _ = handle.stop_tx.send(());
                println!("[server] forward {} stopped (agent disconnected)", id);
            }
        }
    }

    pub async fn register(&self, token: &str, id: String, handle: AgentHandle) {
        let mut agents = self.agents.lock().await;
        let group = agents.entry(token.to_string()).or_default();
        group.insert(id, handle);
    }

    pub async fn unregister(&self, token: &str, id: &str) {
        let mut agents = self.agents.lock().await;
        if let Some(group) = agents.get_mut(token) {
            group.remove(id);
            if group.is_empty() {
                agents.remove(token);
            }
        }
    }

    /// Check if an agent with given (token, id) already exists.
    pub async fn contains_agent(&self, token: &str, id: &str) -> bool {
        let agents = self.agents.lock().await;
        agents
            .get(token)
            .map(|g| g.contains_key(id))
            .unwrap_or(false)
    }

    /// Find an agent by the raw ID (the `provided_id` from the agent).
    /// Searches across all tokens. Returns (token, qualified_id, handle).
    /// Matches if qualified_id ends with `:{id}`, equals `id`, or the normalized (token_id) form equals `id`.
    pub async fn find_agent_by_id(
        &self,
        id: &str,
    ) -> Option<(String, String, AgentHandle)> {
        let agents = self.agents.lock().await;
        for (token, group) in agents.iter() {
            for (k, v) in group.iter() {
                let normalized = k.replace(':', "_").replace('.', "_");
                let suffix = format!(":{}", id);
                if *k == id || k.ends_with(&suffix) || normalized == id {
                    return Some((token.clone(), k.clone(), AgentHandle {
                        name: v.name.clone(),
                        addr: v.addr,
                        connected_at: v.connected_at,
                        tx: v.tx.clone(),
                        ip_location: v.ip_location.clone(),
                    }));
                }
            }
        }
        None
    }

    /// Manually ping an agent to check if it's alive.
    /// Returns `true` if agent responded with PONG within 30 seconds.
    pub async fn ping_agent(&self, agent_id: &str) -> bool {
        let (tx, rx) = oneshot::channel();
        {
            let mut pings = self.pending_pings.lock().await;
            pings.insert(agent_id.to_string(), tx);
        }

        // Send PING
        if self.send_to_agent(agent_id, b"PING\n".to_vec()).await.is_err() {
            let mut pings = self.pending_pings.lock().await;
            pings.remove(agent_id);
            return false;
        }

        // Wait for PONG with 30s timeout
        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(true)) => true,
            _ => {
                let mut pings = self.pending_pings.lock().await;
                pings.remove(agent_id);
                false
            }
        }
    }
}

#[derive(serde::Serialize, Clone)]
pub struct AgentInfo {
    pub id: String,
    pub name: String,
    pub addr: String,
    pub uptime_secs: u64,
    pub token: String,
    /// true = online now, false = offline (in history list)
    pub online: bool,
    /// Unix epoch seconds for offline agents, 0 for online
    pub last_seen: u64,
    /// Approximate unix epoch seconds when the agent connected (online only)
    pub connected_at: u64,
    /// IP geolocation string (e.g., "中国 广东省 深圳市 电信")
    pub ip_location: String,
}

async fn read_line(stream: &mut TcpStream, buf: &mut Vec<u8>, cipher: Option<&XorCipher>) -> anyhow::Result<String> {
    let mut tmp = [0u8; 1024];
    loop {
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            let line_bytes: Vec<u8> = buf.drain(..=pos).collect();
            return Ok(String::from_utf8_lossy(&line_bytes)
                .trim_end_matches('\n')
                .to_string());
        }
        // Safety limit: don't buffer more than 64KB (prevents OOM from garbage)
        if buf.len() > 65536 {
            anyhow::bail!("line too long (>64KB)");
        }
        match stream.read(&mut tmp).await {
            Ok(0) => anyhow::bail!("connection closed"),
            Ok(n) => {
                // Decrypt the chunk before appending
                if let Some(c) = cipher {
                    c.decrypt(&mut tmp[..n]);
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            Err(e) => anyhow::bail!("read error: {}", e),
        }
    }
}

/// Write data to socket with optional XOR encryption.
async fn xor_write(socket: &mut TcpStream, data: &[u8], cipher: Option<&XorCipher>) -> anyhow::Result<()> {
    if let Some(c) = cipher {
        let mut encrypted = data.to_vec();
        c.encrypt(&mut encrypted);
        socket.write_all(&encrypted).await?;
    } else {
        socket.write_all(data).await?;
    }
    Ok(())
}

pub async fn run_agent_listener(
    manager: Arc<AgentManager>,
    addr: &str,
    allow_tokens: Vec<String>,
    block_tokens: Vec<String>,
    crypto_key: String,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("[server] agent listener ready on {}", addr);

    // Background task: clean up expired bans every 60 seconds
    let ban_cleaner = manager.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            ban_cleaner.cleanup_bans().await;
        }
    });

    loop {
        let (socket, peer) = listener.accept().await?;
        let mgr = manager.clone();
        let allow = allow_tokens.clone();
        let block = block_tokens.clone();
        let key = crypto_key.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_agent(mgr, socket, peer, &allow, &block, &key).await {
                eprintln!("[server] agent session error ({}): {}", peer, e);
            }
        });
    }
}

async fn handle_agent(
    manager: Arc<AgentManager>,
    mut socket: TcpStream,
    peer: SocketAddr,
    allow_tokens: &[String],
    block_tokens: &[String],
    crypto_key: &str,
) -> anyhow::Result<()> {
    let cipher = XorCipher::new(crypto_key);
    // Use Option<&XorCipher> for readability
    let c_opt: Option<&XorCipher> = if cipher.is_enabled() { Some(&cipher) } else { None };
    let peer_ip = peer.ip().to_string();

    // ── IP ban check ──────────────────────────────────────────────
    if manager.is_ip_banned(&peer_ip).await {
        return Ok(());
    }

    set_tcp_keepalive(&socket);

    // ── Handshake with timeout ────────────────────────────────────
    let mut hello_buf: Vec<u8> = Vec::with_capacity(256);
    let line = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        read_line(&mut socket, &mut hello_buf, c_opt),
    )
    .await
    .map_err(|_| anyhow::anyhow!("handshake timeout"))??;

    let parts: Vec<&str> = line.trim().splitn(4, ' ').collect();
    if parts.len() < 2 || parts[0] != "HELLO" {
        if manager.record_handshake_failure(&peer_ip).await {
            manager.ban_ip(&peer_ip).await;
        } else {
            let fail_count = manager.ban_failures.lock().await.get(&peer_ip).map_or(0, |v| v.len());
            println!(
                "[server] invalid handshake from {} (failure #{})",
                peer_ip, fail_count
            );
        }
        return Ok(());
    }
    let name = parts[1].to_string();

    let (agent_id, provided_token) = if parts.len() >= 4 {
        (parts[2].to_string(), parts[3])
    } else {
        (name.clone(), if parts.len() > 2 { parts[2] } else { "" })
    };

    // ---- Token allow / block list check ----
    if !allow_tokens.is_empty() && !allow_tokens.contains(&provided_token.to_string()) {
        eprintln!(
            "[server] agent {} rejected: token {:?} not in allow list (from {})",
            name, provided_token, peer
        );
        let _ = xor_write(&mut socket, b"REJECT token not allowed\n", c_opt).await;
        return Ok(());
    }
    if !block_tokens.is_empty() && block_tokens.contains(&provided_token.to_string()) {
        eprintln!(
            "[server] agent {} rejected: token {:?} is blocked (from {})",
            name, provided_token, peer
        );
        let _ = xor_write(&mut socket, b"REJECT token blocked\n", c_opt).await;
        return Ok(());
    }

    let qualified_id = AgentManager::qualified_id(&provided_token, &agent_id);

    if manager
        .contains_agent(&provided_token, &qualified_id)
        .await
    {
        println!(
            "[server] agent {} reconnecting, will replace old session",
            qualified_id
        );
    }

    println!(
        "[server] agent joined: id={} name={} addr={} token={:?}",
        qualified_id,
        name,
        peer,
        if provided_token.is_empty() {
            None
        } else {
            Some(&provided_token)
        }
    );

    let (reader, mut writer) = socket.into_split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);

    // Look up IP geolocation
    let ip_location = manager.ip_lookup.lookup(&peer.ip().to_string()).unwrap_or_default();

    manager
        .register(
            &provided_token,
            qualified_id.clone(),
            AgentHandle {
                name: name.clone(),
                addr: peer,
                connected_at: std::time::Instant::now(),
                tx,
                ip_location,
            },
        )
        .await;

    // ── Wrap writer task with optional XOR encryption ────────────
    let cipher_arc = Arc::new(cipher);
    let wc = cipher_arc.clone();
    let write_task = tokio::spawn(async move {
        while let Some(mut data) = rx.recv().await {
            wc.encrypt(&mut data);
            if writer.write_all(&data).await.is_err() {
                break;
            }
            let _ = writer.flush().await;
        }
    });

    let read_mgr = manager.clone();
    let read_agent_id = qualified_id.clone();
    let read_token = provided_token;
    let rc = cipher_arc.clone();
    let read_task = tokio::spawn(async move {
        let mut reader = reader;
        let mut buf: Vec<u8> = Vec::with_capacity(4096);
        let mut tmp = [0u8; 4096];

        // ── Heartbeat state ──────────────────────────────────────────
        // Server sends PING every 30 min and expects PONG within 60 s.
        let mut ping_sent: Option<Instant> = None; // when PING was sent
        let mut next_hb: tokio::time::Instant =
            tokio::time::Instant::now() + Duration::from_secs(30 * 60);

        loop {
            // ── Heartbeat timeout check (before reading) ──────────────
            if let Some(sent_at) = ping_sent {
                if sent_at.elapsed() > Duration::from_secs(60) {
                    eprintln!("[server] heartbeat timeout for {}", read_agent_id);
                    return; // disconnect
                }
            }

            // ── Find next complete line ───────────────────────────────
            let pos = loop {
                if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    break pos;
                }
                if buf.len() > 65536 {
                    eprintln!(
                        "[server] {} protocol error: buffer too large",
                        read_agent_id
                    );
                    return;
                }

                // Wait for data OR heartbeat tick
                tokio::select! {
                    result = reader.read(&mut tmp) => {
                        match result {
                            Ok(0) => return,
                            Ok(n) => {
                                rc.decrypt(&mut tmp[..n]);
                                buf.extend_from_slice(&tmp[..n]);
                            }
                            Err(e) => {
                                eprintln!("[server] {} read error: {}", read_agent_id, e);
                                return;
                            }
                        }
                    }
                    _ = tokio::time::sleep_until(next_hb) => {
                        if read_mgr.send_to_agent(&read_agent_id, b"PING\n".to_vec()).await.is_err() {
                            return;
                        }
                        ping_sent = Some(Instant::now());
                        next_hb = tokio::time::Instant::now() + Duration::from_secs(30 * 60);
                    }
                }

                // Re-check heartbeat timeout after waking
                if let Some(sent_at) = ping_sent {
                    if sent_at.elapsed() > Duration::from_secs(60) {
                        eprintln!("[server] heartbeat timeout for {}", read_agent_id);
                        return;
                    }
                }
            };

            // ── Process one complete line ─────────────────────────────
            let line_bytes: Vec<u8> = buf.drain(..=pos).collect();
            let line = String::from_utf8_lossy(&line_bytes)
                .trim_end_matches('\n')
                .to_string();

            let parts: Vec<&str> = line.splitn(4, ' ').collect();
            match parts.first().map(|s| *s) {
                Some("PING") => {
                    let _ = read_mgr
                        .send_to_agent(&read_agent_id, b"PONG\n".to_vec())
                        .await;
                }
                Some("PONG") => {
                    // ── Clear heartbeat ───────────────────────────
                    ping_sent = None;
                    next_hb = tokio::time::Instant::now() + Duration::from_secs(30 * 60);
                    // ── Resolve manual ping if any ────────────────
                    let mut pings = read_mgr.pending_pings.lock().await;
                    if let Some(sender) = pings.remove(&read_agent_id) {
                        let _ = sender.send(true);
                    }
                }
                Some("EXEC_RESULT") => {
                    if parts.len() >= 3 {
                        let op_id = parts[1].to_string();
                        let code: i32 = parts[2].parse().unwrap_or(-1);
                        let mut out_buf: Vec<u8> = Vec::new();
                        loop {
                            let nl = buf.iter().position(|&b| b == b'\n');
                            match nl {
                                Some(p) => {
                                    if &buf[..p] == b".END" {
                                        buf.drain(..p + 1);
                                        break;
                                    }
                                    let row: Vec<u8> = buf.drain(..p + 1).collect();
                                    out_buf.extend_from_slice(&row);
                                }
                                None => match reader.read(&mut tmp).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        rc.decrypt(&mut tmp[..n]);
                                        buf.extend_from_slice(&tmp[..n]);
                                    }
                                    Err(_) => break,
                                },
                            }
                        }
                        let output = String::from_utf8_lossy(&out_buf).to_string();
                        let mut pending = read_mgr.pending_results.lock().await;
                        if let Some(sender) = pending.remove(&op_id) {
                            let _ = sender.send(ExecResult { code, output }).await;
                        }
                    }
                }
                Some("TUN_OK") => {
                    println!("[server] {}", line);
                }
                Some("TUN_DATA") => {
                    if parts.len() >= 3 {
                        let tunnel_id = parts[1].to_string();
                        let data_len: usize = parts[2].parse().unwrap_or(0);
                        if data_len > 0 {
                            while buf.len() < data_len {
                                match reader.read(&mut tmp).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        rc.decrypt(&mut tmp[..n]);
                                        buf.extend_from_slice(&tmp[..n]);
                                    }
                                    Err(_) => break,
                                }
                            }
                            let actual = data_len.min(buf.len());
                            let data: Vec<u8> = buf.drain(..actual).collect();

                            let mut tunnels = read_mgr.tunnels.lock().await;
                            if let Some(tun) = tunnels.get_mut(&tunnel_id) {
                                if let Some(client) = &mut tun.client {
                                    let _ = client.write_all(&data).await;
                                    let _ = client.flush().await;
                                }
                            }
                        }
                    }
                }
                Some("TUN_CLOSE") => {
                    if parts.len() >= 2 {
                        let tunnel_id = parts[1].to_string();
                        println!("[server] tunnel {} closed by agent", tunnel_id);
                        let mut tunnels = read_mgr.tunnels.lock().await;
                        tunnels.remove(&tunnel_id);
                    }
                }
                _ => {}
            }
        }
    });

    let _ = tokio::join!(write_task, read_task);

    // Save offline record before cleanup
    let last_seen = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    manager
        .add_offline(AgentInfo {
            id: qualified_id.clone(),
            name: name.clone(),
            addr: peer.to_string(),
            uptime_secs: 0,
            token: provided_token.to_string(),
            online: false,
            last_seen,
            connected_at: 0,
            ip_location: String::new(),
        })
        .await;

    // Cleanup on disconnect
    manager.unregister(&read_token, &qualified_id).await;
    let mut tunnels = manager.tunnels.lock().await;
    tunnels.retain(|_, t| t.agent_id != qualified_id);
    drop(tunnels);
    manager.stop_all_forwards_for_agent(&qualified_id).await;

    println!("[server] agent left: {} (token: {:?})", qualified_id, read_token);
    Ok(())
}

pub async fn start_port_forward(
    manager: Arc<AgentManager>,
    agent_id: String,
    agent_name: String,
    local_addr: String,
    server_port: u16,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", server_port)).await?;
    let forward_id = format!("fwd-{}-{}", agent_id, server_port);
    println!(
        "[server] port forward {}: 0.0.0.0:{} -> agent[{}]:{}",
        forward_id, server_port, agent_id, local_addr
    );

    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();

    {
        let mut forwards = manager.forwards.lock().await;
        // Remove old forward on same port if exists
        forwards.retain(|_, h| h.server_port != server_port || h.agent_id != agent_id);
        forwards.insert(
            forward_id.clone(),
            ForwardHandle {
                agent_id: agent_id.clone(),
                agent_name: agent_name.clone(),
                local_addr: local_addr.clone(),
                server_port,
                stop_tx,
            },
        );
    }

    let mgr = manager.clone();
    let fid = forward_id.clone();
    let aid = agent_id.clone();
    let lad = local_addr.clone();
    tokio::spawn(async move {
        let mut counter: u64 = 0;

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((client, _)) => {
                            let tunnel_id = format!("tun-{}-{}", aid, counter);
                            counter += 1;

                            let (user_reader, user_writer) = client.into_split();

                            {
                                let mut tunnels = mgr.tunnels.lock().await;
                                tunnels.insert(
                                    tunnel_id.clone(),
                                    TunnelHandle {
                                        agent_id: aid.clone(),
                                        client: Some(user_writer),
                                    },
                                );
                            }

                            let open_msg = format!("TUN_OPEN {} {}\n", tunnel_id, lad).into_bytes();
                            if let Err(e) = mgr.send_to_agent(&aid, open_msg).await {
                                eprintln!("[server] send TUN_OPEN failed: {}", e);
                                mgr.tunnels.lock().await.remove(&tunnel_id);
                                continue;
                            }

                            let mgr2 = mgr.clone();
                            let tid = tunnel_id.clone();
                            let aid2 = aid.clone();
                            tokio::spawn(async move {
                                let _ = pipe_user_to_agent(mgr2.clone(), &tid, &aid2, user_reader).await;
                                let mut tunnels = mgr2.tunnels.lock().await;
                                tunnels.remove(&tid);
                                let close_msg = format!("TUN_CLOSE {}\n", tid).into_bytes();
                                let _ = mgr2.send_to_agent(&aid2, close_msg).await;
                            });
                        }
                        Err(e) => {
                            eprintln!("[server] forward accept error: {}", e);
                            break;
                        }
                    }
                }
                _ = &mut stop_rx => {
                    println!("[server] forward {} stopped by user", fid);
                    break;
                }
            }
        }

        mgr.forwards.lock().await.remove(&fid);
    });

    Ok(())
}

async fn pipe_user_to_agent(
    mgr: Arc<AgentManager>,
    tunnel_id: &str,
    agent_id: &str,
    mut user_reader: tokio::net::tcp::OwnedReadHalf,
) -> std::io::Result<()> {
    let mut buf = [0u8; 8192];
    loop {
        let n = user_reader.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        let mut frame = format!("TUN_DATA {} {}\n", tunnel_id, n).into_bytes();
        frame.extend_from_slice(&buf[..n]);

        if mgr.send_to_agent(agent_id, frame).await.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "agent gone",
            ));
        }
    }
}

/// Start an HTTP reverse proxy that routes by Host header.
///
/// When a request arrives with `Host: <agent_id>.<domain>:<port>`, the proxy
/// extracts `<agent_id>`, looks up the online agent, and forwards the entire
/// HTTP request to the agent's local port 80 via the existing tunnel mechanism.
///
/// # Arguments
/// * `manager` - The agent manager
/// * `http_proxy_port` - The local port to listen on (e.g., 80, 8080)
/// * `domain` - The domain suffix to strip from Host headers (e.g., "dome.com")
///   If empty, the entire Host value before the port is treated as the agent ID.
pub async fn start_http_proxy(
    manager: Arc<AgentManager>,
    http_proxy_port: u16,
    domain: &str,
) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", http_proxy_port);
    let listener = TcpListener::bind(&addr).await?;
    println!(
        "[server] HTTP proxy listening on {} (domain: {})",
        addr,
        if domain.is_empty() { "(any)" } else { domain }
    );

    loop {
        let (client, peer) = listener.accept().await?;
        let mgr = manager.clone();
        let domain_owned = domain.to_string();
        tokio::spawn(async move {
            if let Err(e) = handle_http_proxy(mgr, client, &domain_owned).await {
                eprintln!("[server] HTTP proxy error ({}): {}", peer, e);
            }
        });
    }
}

async fn handle_http_proxy(
    mgr: Arc<AgentManager>,
    mut client: TcpStream,
    domain: &str,
) -> anyhow::Result<()> {
    let peer = client.peer_addr().ok();
    eprintln!("[HTTP proxy] new connection from {:?}", peer);
    let _ = client.set_nodelay(true);

    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];

    let header_end = loop {
        let n = client.read(&mut tmp).await?;
        if n == 0 {
            eprintln!(
                "[HTTP proxy] {:?} closed connection after {} bytes (no complete headers)",
                peer, buf.len()
            );
            anyhow::bail!("connection closed before headers complete");
        }
        eprintln!("[HTTP proxy] {:?} read {} bytes", peer, n);
        buf.extend_from_slice(&tmp[..n]);

        if let Some(pos) = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
        {
            break pos + 4;
        }

        if buf.len() > 65536 {
            anyhow::bail!("request headers too large");
        }
    };

    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    eprintln!("[HTTP proxy] {:?} FULL HEADERS:\n{}", peer, header_str);

    let host = header_str
        .lines()
        .find_map(|line| {
            let line = line.trim();
            if line.to_lowercase().starts_with("host:") {
                Some(line[5..].trim())
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow::anyhow!("missing Host header"))?;
    eprintln!("[HTTP proxy] {:?} Host header: {:?}", peer, host);

    let hostname = host.rsplitn(2, ':').last().unwrap_or(host);
    eprintln!("[HTTP proxy] {:?} hostname (port stripped): {:?}", peer, hostname);

    let agent_id = if domain.is_empty() {
        hostname.to_string()
    } else {
        let domain_dot = format!(".{}", domain);
        if hostname.ends_with(&domain_dot) {
            let subdomain = &hostname[..hostname.len() - domain_dot.len()];
            eprintln!(
                "[HTTP proxy] {:?} subdomain='{:?}' domain='{:?}'",
                peer, subdomain, domain
            );
            subdomain.to_string()
        } else {
            eprintln!(
                "[HTTP proxy] {:?} hostname {:?} does not end with {:?}, using as-is",
                peer, hostname, domain_dot
            );
            hostname.to_string()
        }
    };
    eprintln!("[HTTP proxy] {:?} raw agent_id: {:?}", peer, agent_id);

    if agent_id.is_empty() {
        anyhow::bail!("empty agent ID from Host: {}", host);
    }

    let agent_id = agent_id
        .chars()
        .map(|c| match c {
            ':' | '.' | '/' | '?' | '#' | '@' | '!' | '$' | '&' | '\'' | '(' | ')'
            | '*' | '+' | ',' | ';' | '=' | '%' | '^' | '`' | '{' | '|' | '}' | '~' | ' ' => '_',
            _ => c,
        })
        .collect::<String>();
    eprintln!("[HTTP proxy] {:?} sanitized agent_id: {:?}", peer, agent_id);

    let all_agents = mgr.list().await;
    eprintln!(
        "[HTTP proxy] {:?} total registered agents ({}): {:?}",
        peer,
        all_agents.len(),
        all_agents.iter().map(|a| a.id.clone()).collect::<Vec<_>>()
    );

    let lookup_result = mgr.find_agent_by_id(&agent_id).await;
    match &lookup_result {
        Some((token, qual_id, _)) => {
            eprintln!(
                "[HTTP proxy] {:?} MATCH: token={:?} qualified_id={:?}",
                peer, token, qual_id
            );
        }
        None => {
            eprintln!("[HTTP proxy] {:?} NO MATCH for agent_id={:?}", peer, agent_id);
        }
    }

    let (_, found_qualified, _) = lookup_result
        .ok_or_else(|| anyhow::anyhow!("agent not found: {}", agent_id))?;

    let current_web_agent = {
        let w = mgr.web_agent.lock().await;
        w.clone()
    };
    eprintln!(
        "[HTTP proxy] {:?} check_web_agent: found={:?} selected={:?}",
        peer, found_qualified, current_web_agent
    );
    if !mgr.check_web_agent(&found_qualified).await {
        eprintln!(
            "[HTTP proxy] {:?} DENIED: not the selected web agent",
            peer
        );
        anyhow::bail!(
            "agent {} is not the currently selected web agent",
            found_qualified
        );
    }
    eprintln!("[HTTP proxy] {:?} check_web_agent PASSED", peer);

    // ── Create tunnel to agent's port 80 ───────────────────────────
    let tunnel_id = format!("http-{}-{}", found_qualified, std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros());
    let local_addr = "127.0.0.1:80".to_string();
    eprintln!(
        "[HTTP proxy] {:?} creating tunnel {} → agent port 80",
        peer, tunnel_id
    );

    let (user_reader, user_writer) = client.into_split();

    {
        let mut tunnels = mgr.tunnels.lock().await;
        tunnels.insert(
            tunnel_id.clone(),
            TunnelHandle {
                agent_id: found_qualified.clone(),
                client: Some(user_writer),
            },
        );
    }

    // Send TUN_OPEN to agent
    let open_msg = format!("TUN_OPEN {} {}\n", tunnel_id, local_addr).into_bytes();
    mgr.send_to_agent(&found_qualified, open_msg).await?;

    // ── Forward the already-read initial data (HTTP headers + any body) ──
    let initial_data = &buf[..];
    if !initial_data.is_empty() {
        let frame = format!("TUN_DATA {} {}\n", tunnel_id, initial_data.len());
        let mut msg = frame.into_bytes();
        msg.extend_from_slice(initial_data);
        if mgr.send_to_agent(&found_qualified, msg).await.is_err() {
            mgr.tunnels.lock().await.remove(&tunnel_id);
            anyhow::bail!("agent disconnected");
        }
    }

    // ── Pipe remaining request body to agent ───────────────────────
    let mgr2 = mgr.clone();
    let tid = tunnel_id.clone();
    let aid = found_qualified.clone();
    tokio::spawn(async move {
        let _ = pipe_user_to_agent(mgr2.clone(), &tid, &aid, user_reader).await;
        let mut tunnels = mgr2.tunnels.lock().await;
        tunnels.remove(&tid);
        let close_msg = format!("TUN_CLOSE {}\n", tid).into_bytes();
        let _ = mgr2.send_to_agent(&aid, close_msg).await;
    });

    // The tunnel's write half (user_writer) is already registered in tunnels;
    // agent responses flow back through the tunnel mechanism via TUN_DATA from agent.
    // No further action needed here — the spawned task handles lifecycle.

    Ok(())
}