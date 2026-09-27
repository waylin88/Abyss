mod crypto;
mod dns;

use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crypto::XorCipher;

const BUF_SIZE: usize = 8192;
const TICK_MS: u64 = 100;

struct TunnelState {
    local_stream: TcpStream,
}

fn parse_arg(args: &[String], name: &str) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == name || args[i] == format!("-{}", name.chars().nth(1).unwrap_or('?')) {
            return args.get(i + 1).cloned();
        }
        i += 1;
    }
    None
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

#[cfg(target_os = "linux")]
fn hide_args(argv0: &str) {
    let maps = match std::fs::read_to_string("/proc/self/maps") {
        Ok(s) => s,
        Err(_) => return,
    };

    let marker = argv0.as_bytes();
    if marker.is_empty() {
        return;
    }

    let mut stack_seg: Option<(usize, usize)> = None;
    let mut highest_rwx: Option<(usize, usize)> = None;

    for line in maps.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let perms = parts[1];
        if !perms.contains('w') {
            continue;
        }
        let range: Vec<&str> = parts[0].split('-').collect();
        if range.len() != 2 {
            continue;
        }
        let seg_start = match usize::from_str_radix(range[0], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let seg_end = match usize::from_str_radix(range[1], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if seg_end <= seg_start {
            continue;
        }
        let seg_len = seg_end - seg_start;
        if seg_len > 64 * 1024 * 1024 {
            continue;
        }
        let label = if parts.len() >= 6 {
            parts.last().unwrap_or(&"")
        } else {
            ""
        };

        if label.contains("stack") {
            stack_seg = Some((seg_start, seg_len));
        } else if highest_rwx.is_none() || seg_end > highest_rwx.unwrap().0 + highest_rwx.unwrap().1 {
            highest_rwx = Some((seg_start, seg_len));
        }
    }

    let target = stack_seg.as_ref().or(highest_rwx.as_ref());
    let (seg_start, seg_len) = match target {
        Some(v) => v,
        None => return,
    };
    let seg_end = seg_start + seg_len;

    let seg = unsafe { std::slice::from_raw_parts(*seg_start as *const u8, *seg_len) };

    let mut window_end = *seg_len;
    let mut window_start = window_end.saturating_sub(16384);

    loop {
        let mut pos = window_start;
        while pos + marker.len() < window_end {
            if &seg[pos..pos + marker.len()] == marker
                && pos + marker.len() < seg.len()
                && seg[pos + marker.len()] == 0
            {
                let arg_start = *seg_start + pos;
                let mut total = marker.len() + 1;
                let mut scan = pos + marker.len() + 1;
                while scan < seg.len() && total < 8192 {
                    if seg[scan] == 0 {
                        if scan + 1 < seg.len() && seg[scan + 1] == 0 {
                            total += 1;
                            break;
                        }
                        total += 1;
                        scan += 1;
                        continue;
                    }
                    total += 1;
                    scan += 1;
                }
                if arg_start + total > seg_end || total == 0 {
                    pos += 1;
                    continue;
                }

                let argv_slice = unsafe {
                    std::slice::from_raw_parts_mut(arg_start as *mut u8, total)
                };
                for byte in argv_slice.iter_mut() {
                    *byte = 0;
                }
                let name = b"rtragent";
                let copy_len = name.len().min(argv_slice.len().saturating_sub(1));
                argv_slice[..copy_len].copy_from_slice(&name[..copy_len]);
                argv_slice[copy_len] = 0;
                return;
            }
            pos += 1;
        }
        if window_start == 0 {
            break;
        }
        window_end = window_start;
        window_start = window_end.saturating_sub(16384);
    }
}

#[cfg(not(target_os = "linux"))]
fn hide_args(_argv0: &str) {}

#[cfg(target_os = "linux")]
fn set_tcp_keepalive(stream: &std::net::TcpStream) {
    use std::os::unix::io::AsRawFd;
    #[link(name = "c")]
    extern "C" {
        fn setsockopt(fd: i32, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
    }
    const SOL_SOCKET: i32 = 1;
    const SO_KEEPALIVE: i32 = 9;
    const IPPROTO_TCP: i32 = 6;
    const TCP_KEEPIDLE: i32 = 4;
    const TCP_KEEPINTVL: i32 = 5;
    const TCP_KEEPCNT: i32 = 6;
    let fd = stream.as_raw_fd();
    let one: i32 = 1;
    unsafe {
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one as *const _ as *const u8, 4);
        let idle: i32 = 30;
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle as *const _ as *const u8, 4);
        let intv: i32 = 15;
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intv as *const _ as *const u8, 4);
        let cnt: i32 = 3;
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt as *const _ as *const u8, 4);
    }
}

#[cfg(not(target_os = "linux"))]
fn set_tcp_keepalive(_stream: &std::net::TcpStream) {}

#[cfg(target_os = "linux")]
fn auto_name() -> String {
    let (_code, out) = run_cmd("nvram get productid");
    let trimmed = out.trim().to_string();
    if !trimmed.is_empty() {
        return trimmed;
    }
    "router".to_string()
}

#[cfg(not(target_os = "linux"))]
fn auto_name() -> String {
    "router".to_string()
}

#[cfg(target_os = "linux")]
fn auto_id() -> String {
    let (_code, raw) = run_cmd("lan_eeprom_mac");

    for line in raw.lines() {
        for word in line.split(|c: char| !c.is_ascii_hexdigit() && c != ':') {
            let colons: Vec<&str> = word.split(':').filter(|s| !s.is_empty()).collect();
            if colons.len() == 6 && colons.iter().all(|s| s.len() == 2) {
                return colons.join("").to_lowercase();
            }
        }
    }

    String::new()
}

#[cfg(not(target_os = "linux"))]
fn auto_id() -> String {
    String::new()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let argv0 = args.first().cloned().unwrap_or_default();
    hide_args(&argv0);

    if args.len() >= 2 && (args[1] == "-h" || args[1] == "--help") {
        eprintln!("rtragent - lightweight router agent");
        eprintln!();
        eprintln!("USAGE: rtragent --server <addr> [--token <token>] [--name <name>] [--id <id>] [--crypto-key <key>] [--crypto-key-no]");
        eprintln!();
        eprintln!("OPTIONS:");
        eprintln!("  -s, --server <addr>       Server address (default: dome.y-lin.wang:46293)");
        eprintln!("  -t, --token <token>       Auth token (optional)");
        eprintln!("  -n, --name <name>         Agent display name (default: router)");
        eprintln!("  -i, --id <id>             Unique device ID. Server uses it to");
        eprintln!("                             identify this agent across reconnections.");
        eprintln!("                             If not set, server generates one.");
        eprintln!("  -k, --crypto-key <key>    XOR encryption key (must match server).");
        eprintln!("                             Default: Zzb33cANnGVGdQWe");
        eprintln!("      --crypto-key-no       Disable XOR encryption");
        eprintln!("  -d, --dns <dns>           Custom DNS server (default: 223.5.5.5). Override");
        eprintln!("                             when the default DNS cannot resolve the domain.");
        eprintln!("  -h, --help                Print this help");
        eprintln!();
        eprintln!("EXAMPLE:");
        eprintln!("    rtragent --server 1.2.3.4:9527 --token mysecret --name my-router --id AA:BB:CC:DD:EE:FF --crypto-key MyKey123");
        return;
    }

    let server = parse_arg(&args, "--server")
        .or_else(|| parse_arg(&args, "-s"))
        .unwrap_or_else(|| "dome.y-lin.wang:46293".to_string());
    let token = parse_arg(&args, "--token")
        .or_else(|| parse_arg(&args, "-t"))
        .unwrap_or_default();
    let name = parse_arg(&args, "--name")
        .or_else(|| parse_arg(&args, "-n"))
        .unwrap_or_else(auto_name);
    let id = parse_arg(&args, "--id")
        .or_else(|| parse_arg(&args, "-i"))
        .unwrap_or_else(auto_id);
    let crypto_key = if has_flag(&args, "--crypto-key-no") {
        String::new()
    } else {
        parse_arg(&args, "--crypto-key")
            .or_else(|| parse_arg(&args, "-k"))
            .unwrap_or_else(|| "Zzb33cANnGVGdQWe".to_string())
    };
    let dns_server = parse_arg(&args, "--dns")
        .or_else(|| parse_arg(&args, "-d"))
        .unwrap_or_else(|| "223.5.5.5".to_string());

    let cipher = XorCipher::new(&crypto_key);
    if cipher.is_enabled() {
        eprintln!("[rtragent] XOR encryption enabled");
    }

    let dns_is_custom = dns_server != "223.5.5.5";
    let mut resolver = dns::DnsResolver::new(&dns_server);
    if dns_is_custom {
        eprintln!("[rtragent] using custom DNS resolver");
    }

    loop {
        cipher.reset();
        let server_addr = dns::resolve_server_addr(&server, &mut resolver);
        eprintln!("[rtragent] connecting to server as {}", name);
        let socket_addrs: Vec<std::net::SocketAddr> = match std::net::ToSocketAddrs::to_socket_addrs(&server_addr) {
            Ok(iter) => iter.collect(),
            Err(_) => {
                eprintln!("[rtragent] invalid server address");
                thread::sleep(Duration::from_secs(5));
                continue;
            }
        };
        let mut connected = None;
        for sa in &socket_addrs {
            if let Ok(s) = TcpStream::connect_timeout(sa, Duration::from_secs(10)) {
                connected = Some(s);
                break;
            }
        }
        match connected {
            Some(stream) => {
                let _ = stream.set_nodelay(true);
                #[cfg(not(windows))]
                set_tcp_keepalive(&stream);

                let mut s = stream;
                let hello = if id.is_empty() {
                    format!("HELLO {} {}\n", name, token)
                } else {
                    format!("HELLO {} {} {}\n", name, id, token)
                };
                let mut hello_bytes = hello.into_bytes();
                cipher.encrypt(&mut hello_bytes);
                if s.write_all(&hello_bytes).is_err() {
                    thread::sleep(Duration::from_secs(3));
                    continue;
                }
                eprintln!("[rtragent] connected");

                let tunnels = Arc::new(Mutex::new(HashMap::<String, TunnelState>::new()));

                if let Err(_) = run_session(&mut s, tunnels.clone(), &cipher) {
                    eprintln!("[rtragent] session terminated");
                }
            }
            None => {
                eprintln!("[rtragent] connect failed, retry in 5s...");
            }
        }
        thread::sleep(Duration::from_secs(5));
    }
}

/// XOR-encrypt a byte slice and write it to the stream.
fn xor_write(stream: &mut TcpStream, data: &[u8], cipher: &XorCipher) {
    let mut encrypted = data.to_vec();
    cipher.encrypt(&mut encrypted);
    let _ = stream.write_all(&encrypted);
}

fn run_session(
    stream: &mut TcpStream,
    tunnels: Arc<Mutex<HashMap<String, TunnelState>>>,
    cipher: &XorCipher,
) -> Result<(), String> {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(TICK_MS)));
    let mut buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut tmp = [0u8; BUF_SIZE];
    let mut last_ping = std::time::Instant::now();

    let (tx_pending, rx_pending) = std::sync::mpsc::channel::<(String, Result<TcpStream, String>)>();

    loop {
        while let Ok((tid, result)) = rx_pending.try_recv() {
            match result {
                Ok(local) => {
                    let _ = local.set_nodelay(true);
                    let _ = local.set_read_timeout(Some(Duration::from_millis(TICK_MS)));
                    eprintln!("[rtragent] tunnel {} opened", tid);
                    tunnels.lock().unwrap().insert(
                        tid.clone(),
                        TunnelState { local_stream: local },
                    );
                    xor_write(
                        stream,
                        format!("TUN_OK {}\n", tid).as_bytes(),
                        cipher,
                    );
                    let _ = stream.flush();
                }
                Err(_) => {
                    eprintln!("[rtragent] tunnel {} connect failed", tid);
                    xor_write(
                        stream,
                        format!("TUN_CLOSE {}\n", tid).as_bytes(),
                        cipher,
                    );
                    let _ = stream.flush();
                }
            }
        }

        match stream.read(&mut tmp) {
            Ok(0) => {
                eprintln!("[rtragent] server disconnected");
                return Ok(());
            }
            Ok(n) => {
                cipher.decrypt(&mut tmp[..n]);
                buf.extend_from_slice(&tmp[..n]);
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                {
                    if last_ping.elapsed() > Duration::from_secs(20) {
                        xor_write(stream, b"PING\n", cipher);
                        let _ = stream.flush();
                        last_ping = std::time::Instant::now();
                    }
                    flush_tunnels(stream, &tunnels, cipher);
                    continue;
                }
                return Err(format!("read error: {}", e));
            }
        }

        loop {
            let nl = buf.iter().position(|&b| b == b'\n');
            match nl {
                Some(pos) => {
                    let line: Vec<u8> = buf.drain(..=pos).collect();
                    let line_str = String::from_utf8_lossy(&line)
                        .trim_end_matches('\n')
                        .to_string();
                    if line_str.is_empty() {
                        continue;
                    }

                    let parts: Vec<&str> = line_str.splitn(4, ' ').collect();
                    match parts.first().map(|s| *s) {
                        Some("PING") => {
                            xor_write(stream, b"PONG\n", cipher);
                            let _ = stream.flush();
                        }
                        Some("PONG") => {
                        }
                        Some("EXEC") => {
                            if parts.len() >= 3 {
                                let op_id = parts[1];
                                let cmd = parts[2];
                                let (code, out) = run_cmd(cmd);
                                let header = format!("EXEC_RESULT {} {}\n", op_id, code);
                                xor_write(stream, header.as_bytes(), cipher);
                                xor_write(stream, out.as_bytes(), cipher);
                                xor_write(stream, b"\n.END\n", cipher);
                                let _ = stream.flush();
                            }
                        }
                        Some("TUN_OPEN") => {
                            if parts.len() >= 3 {
                                let tunnel_id = parts[1].to_string();
                                let local_addr = parts[2].to_string();
                                let tx = tx_pending.clone();
                                if let Ok(sock_addrs) = std::net::ToSocketAddrs::to_socket_addrs(&local_addr) {
                                    let sa: Vec<_> = sock_addrs.collect();
                                    thread::spawn(move || {
                                        let mut res = Err("no addresses".to_string());
                                        for addr in sa {
                                            if let Ok(s) = TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
                                                res = Ok(s);
                                                break;
                                            }
                                        }
                                        let _ = tx.send((tunnel_id, res));
                                    });
                                } else {
                                    eprintln!("[rtragent] tunnel {} invalid address", tunnel_id);
                                    xor_write(
                                        stream,
                                        format!("TUN_CLOSE {}\n", tunnel_id).as_bytes(),
                                        cipher,
                                    );
                                    let _ = stream.flush();
                                }
                            }
                        }
                        Some("TUN_DATA") => {
                            if parts.len() >= 3 {
                                let tunnel_id = parts[1].to_string();
                                let data_len: usize = parts[2].parse().unwrap_or(0);
                                if data_len > 0 {
                                    while buf.len() < data_len {
                                        let _ = stream
                                            .set_read_timeout(Some(Duration::from_secs(5)));
                                        match stream.read(&mut tmp) {
                                            Ok(0) => return Ok(()),
                                            Ok(n) => {
                                                cipher.decrypt(&mut tmp[..n]);
                                                buf.extend_from_slice(&tmp[..n]);
                                            }
                                            Err(_) => {
                                                let _ = stream.set_read_timeout(Some(
                                                    Duration::from_millis(TICK_MS),
                                                ));
                                                break;
                                            }
                                        }
                                    }
                                    let _ = stream.set_read_timeout(Some(Duration::from_millis(TICK_MS)));
                                    let actual = data_len.min(buf.len());
                                    let data: Vec<u8> = buf.drain(..actual).collect();

                                    let mut tmap = tunnels.lock().unwrap();
                                    if let Some(tun) = tmap.get_mut(&tunnel_id) {
                                        let _ = tun.local_stream.write_all(&data);
                                        let _ = tun.local_stream.flush();
                                    }
                                }
                            }
                        }
                        Some("TUN_CLOSE") => {
                            if parts.len() >= 2 {
                                let tunnel_id = parts[1].to_string();
                                eprintln!("[rtragent] tunnel {} closed by server", tunnel_id);
                                tunnels.lock().unwrap().remove(&tunnel_id);
                            }
                        }
                        Some("QUIT") | Some("EXIT") => return Ok(()),
                        _ => {
                            eprintln!("[rtragent] unknown cmd: {}", line_str);
                        }
                    }
                }
                None => break,
            }
        }

        flush_tunnels(stream, &tunnels, cipher);
    }
}

fn flush_tunnels(
    stream: &mut TcpStream,
    tunnels: &Arc<Mutex<HashMap<String, TunnelState>>>,
    cipher: &XorCipher,
) {
    let mut to_send: Vec<(String, Vec<u8>)> = Vec::new();
    let mut to_close: Vec<String> = Vec::new();

    {
        let mut tmap = tunnels.lock().unwrap();
        let mut tmp = [0u8; BUF_SIZE];
        for (tid, tun) in tmap.iter_mut() {
            match tun.local_stream.read(&mut tmp) {
                Ok(n) if n > 0 => {
                    to_send.push((tid.clone(), tmp[..n].to_vec()));
                }
                Ok(0) => {
                    to_close.push(tid.clone());
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                }
                Err(_) => {
                    to_close.push(tid.clone());
                }
                _ => {}
            }
        }
    }

    for (tid, data) in to_send {
        let mut frame = format!("TUN_DATA {} {}\n", tid, data.len()).into_bytes();
        frame.extend_from_slice(&data);
        // Encrypt the entire frame (header + binary data)
        xor_write(stream, &frame, cipher);
    }

    for tid in to_close {
        let close_msg = format!("TUN_CLOSE {}\n", tid);
        xor_write(stream, close_msg.as_bytes(), cipher);
        let mut tmap = tunnels.lock().unwrap();
        tmap.remove(&tid);
    }

    let _ = stream.flush();
}

fn run_cmd(cmd: &str) -> (i32, String) {
    let out = match Command::new("sh").arg("-c").arg(cmd).output() {
        Ok(o) => o,
        Err(e) => return (127, format!("exec error: {}\n", e)),
    };
    let code = out.status.code().unwrap_or(-1);
    let mut s = String::new();
    s.push_str(&String::from_utf8_lossy(&out.stdout));
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (code, s)
}