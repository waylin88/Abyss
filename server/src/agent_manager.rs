use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::Mutex;

pub struct AgentManager {
    agents: Mutex<HashMap<String, AgentHandle>>,
    next_id: AtomicU64,
    tunnels: Mutex<HashMap<String, TunnelHandle>>,
    pending_results: Mutex<HashMap<String, mpsc::Sender<ExecResult>>>,
}

pub struct AgentHandle {
    pub name: String,
    pub addr: SocketAddr,
    pub connected_at: std::time::Instant,
    pub tx: mpsc::Sender<Vec<u8>>,
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

impl AgentManager {
    pub fn new() -> Self {
        Self {
            agents: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            tunnels: Mutex::new(HashMap::new()),
            pending_results: Mutex::new(HashMap::new()),
        }
    }

    pub async fn list(&self) -> Vec<AgentInfo> {
        let agents = self.agents.lock().await;
        agents
            .iter()
            .map(|(k, v)| AgentInfo {
                id: k.clone(),
                name: v.name.clone(),
                addr: v.addr.to_string(),
                uptime_secs: v.connected_at.elapsed().as_secs(),
            })
            .collect()
    }

    pub async fn send_to_agent(&self, agent_id: &str, data: Vec<u8>) -> anyhow::Result<()> {
        let agents = self.agents.lock().await;
        let handle = agents
            .get(agent_id)
            .ok_or_else(|| anyhow::anyhow!("agent not found: {}", agent_id))?;
        handle.tx.send(data).await?;
        Ok(())
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

    pub async fn forward(&self, agent_id: &str, local_addr: &str, server_port: u16) -> anyhow::Result<()> {
        start_port_forward(self.clone(), agent_id.to_string(), local_addr.to_string(), server_port).await
    }

    pub async fn register(&self, id: String, handle: AgentHandle) {
        let mut agents = self.agents.lock().await;
        agents.insert(id, handle);
    }

    pub async fn unregister(&self, id: &str) {
        let mut agents = self.agents.lock().await;
        agents.remove(id);
    }
}

#[derive(serde::Serialize)]
pub struct AgentInfo {
    pub id: String,
    pub name: String,
    pub addr: String,
    pub uptime_secs: u64,
}

async fn read_line(stream: &mut TcpStream, buf: &mut Vec<u8>) -> anyhow::Result<String> {
    let mut tmp = [0u8; 1024];
    loop {
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            let line_bytes: Vec<u8> = buf.drain(..=pos).collect();
            return Ok(String::from_utf8_lossy(&line_bytes)
                .trim_end_matches('\n')
                .to_string());
        }
        match stream.read(&mut tmp).await {
            Ok(0) => anyhow::bail!("connection closed"),
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) => anyhow::bail!("read error: {}", e),
        }
    }
}

pub async fn run_agent_listener(
    manager: Arc<AgentManager>,
    addr: &str,
    token: &str,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("[server] agent listener ready on {}", addr);

    loop {
        let (socket, peer) = listener.accept().await?;
        let mgr = manager.clone();
        let token = token.to_string();
        tokio::spawn(async move {
            if let Err(e) = handle_agent(mgr, socket, peer, &token).await {
                eprintln!("[server] agent session error ({}): {}", peer, e);
            }
        });
    }
}

async fn handle_agent(
    manager: Arc<AgentManager>,
    mut socket: TcpStream,
    peer: SocketAddr,
    token: &str,
) -> anyhow::Result<()> {
    let mut hello_buf: Vec<u8> = Vec::with_capacity(256);
    let line = read_line(&mut socket, &mut hello_buf).await?;

    let parts: Vec<&str> = line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 || parts[0] != "HELLO" {
        anyhow::bail!("invalid handshake: {}", line.trim());
    }
    let name = parts[1].to_string();
    let provided_token = if parts.len() > 2 { parts[2] } else { "" };

    if !token.is_empty() && provided_token != token {
        eprintln!("[server] agent {} rejected (bad token) from {}", name, peer);
        let _ = socket.write_all(b"REJECT bad token\n").await;
        return Ok(());
    }

    let agent_id = format!("{}-{}", name, peer.port());
    println!("[server] agent joined: id={} name={} addr={}", agent_id, name, peer);

    let (reader, mut writer) = socket.into_split();

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);

    manager.register(
        agent_id.clone(),
        AgentHandle {
            name: name.clone(),
            addr: peer,
            connected_at: std::time::Instant::now(),
            tx,
        },
    ).await;

    let write_task = tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if writer.write_all(&data).await.is_err() {
                break;
            }
            let _ = writer.flush().await;
        }
    });

    let read_mgr = manager.clone();
    let read_agent_id = agent_id.clone();
    let read_task = tokio::spawn(async move {
        let mut reader = reader;
        let mut buf: Vec<u8> = Vec::with_capacity(4096);
        let mut tmp = [0u8; 4096];

        loop {
            let mut newline_pos: Option<usize> = None;

            loop {
                if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    newline_pos = Some(pos);
                    break;
                }
                if buf.len() > 65536 {
                    eprintln!("[server] {} protocol error: buffer too large", read_agent_id);
                    return;
                }
                match reader.read(&mut tmp).await {
                    Ok(0) => return,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(e) => {
                        eprintln!("[server] {} read error: {}", read_agent_id, e);
                        return;
                    }
                }
            }

            let pos = newline_pos.unwrap();
            let line_bytes: Vec<u8> = buf.drain(..=pos).collect();
            let line = String::from_utf8_lossy(&line_bytes).trim_end_matches('\n').to_string();

            let parts: Vec<&str> = line.splitn(4, ' ').collect();
            match parts.first().map(|s| *s) {
                Some("PING") => {
                    let _ = read_mgr.send_to_agent(&read_agent_id, b"PONG\n".to_vec()).await;
                }
                Some("PONG") => {}
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
                                None => {
                                    match reader.read(&mut tmp).await {
                                        Ok(0) => break,
                                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                                        Err(_) => break,
                                    }
                                }
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
                                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
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
    manager.unregister(&agent_id).await;
    let mut tunnels = manager.tunnels.lock().await;
    tunnels.retain(|_, t| t.agent_id != agent_id);
    println!("[server] agent left: {}", agent_id);
    Ok(())
}

pub async fn start_port_forward(
    manager: Arc<AgentManager>,
    agent_id: String,
    local_addr: String,
    server_port: u16,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", server_port)).await?;
    println!(
        "[server] port forward 0.0.0.0:{} -> agent[{}]:{}",
        server_port, agent_id, local_addr
    );

    let mgr = manager.clone();
    tokio::spawn(async move {
        let mut counter: u64 = 0;
        loop {
            match listener.accept().await {
                Ok((client, _)) => {
                    let tunnel_id = format!("tun-{}-{}", agent_id, counter);
                    counter += 1;

                    let (user_reader, user_writer) = client.into_split();

                    {
                        let mut tunnels = mgr.tunnels.lock().await;
                        tunnels.insert(
                            tunnel_id.clone(),
                            TunnelHandle {
                                agent_id: agent_id.clone(),
                                client: Some(user_writer),
                            },
                        );
                    }

                    let open_msg = format!("TUN_OPEN {} {}\n", tunnel_id, local_addr).into_bytes();
                    if let Err(e) = mgr.send_to_agent(&agent_id, open_msg).await {
                        eprintln!("[server] send TUN_OPEN failed: {}", e);
                        mgr.tunnels.lock().await.remove(&tunnel_id);
                        continue;
                    }

                    let mgr2 = mgr.clone();
                    let tid = tunnel_id.clone();
                    let aid = agent_id.clone();
                    tokio::spawn(async move {
                        let _ = pipe_user_to_agent(mgr2.clone(), &tid, &aid, user_reader).await;

                        let mut tunnels = mgr2.tunnels.lock().await;
                        tunnels.remove(&tid);

                        let close_msg = format!("TUN_CLOSE {}\n", tid).into_bytes();
                        let _ = mgr2.send_to_agent(&aid, close_msg).await;
                    });
                }
                Err(e) => eprintln!("[server] accept error: {}", e),
            }
        }
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