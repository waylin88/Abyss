use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const BUF_SIZE: usize = 8192;
const TICK_MS: u64 = 100;

struct TunnelState {
    local_stream: TcpStream,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() >= 2 && (args[1] == "-h" || args[1] == "--help") {
        eprintln!("rtragent - lightweight router agent");
        eprintln!();
        eprintln!("USAGE: rtragent <server_addr> [token] [name]");
        eprintln!();
        eprintln!("EXAMPLE:");
        eprintln!("    rtragent 1.2.3.4:9527 mysecret rt-a1b2");
        return;
    }

    let server = args.get(1).map(|s| s.as_str()).unwrap_or("127.0.0.1:9527");
    let token = args.get(2).map(|s| s.as_str()).unwrap_or("");
    let name = args.get(3).map(|s| s.as_str()).unwrap_or("router");

    loop {
        eprintln!("[rtragent] connecting to {} as {}", server, name);
        match TcpStream::connect(server) {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);

                let mut s = stream;
                let hello = format!("HELLO {} {}\n", name, token);
                if s.write_all(hello.as_bytes()).is_err() {
                    thread::sleep(Duration::from_secs(3));
                    continue;
                }
                eprintln!("[rtragent] connected");

                let tunnels = Arc::new(Mutex::new(HashMap::<String, TunnelState>::new()));

                if let Err(e) = run_session(&mut s, tunnels.clone()) {
                    eprintln!("[rtragent] session error: {}", e);
                }
            }
            Err(e) => {
                eprintln!("[rtragent] connect failed: {}, retry in 5s...", e);
            }
        }
        thread::sleep(Duration::from_secs(5));
    }
}

fn run_session(
    stream: &mut TcpStream,
    tunnels: Arc<Mutex<HashMap<String, TunnelState>>>,
) -> Result<(), String> {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(TICK_MS)));
    let mut buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut tmp = [0u8; BUF_SIZE];
    let mut last_ping = std::time::Instant::now();

    loop {
        match stream.read(&mut tmp) {
            Ok(0) => {
                eprintln!("[rtragent] server disconnected");
                return Ok(());
            }
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                {
                    if last_ping.elapsed() > Duration::from_secs(20) {
                        let _ = stream.write_all(b"PING\n");
                        let _ = stream.flush();
                        last_ping = std::time::Instant::now();
                    }
                    flush_tunnels(stream, &tunnels);
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
                            let _ = stream.write_all(b"PONG\n");
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
                                let _ = stream.write_all(header.as_bytes());
                                let _ = stream.write_all(out.as_bytes());
                                let _ = stream.write_all(b"\n.END\n");
                                let _ = stream.flush();
                            }
                        }
                        Some("TUN_OPEN") => {
                            if parts.len() >= 3 {
                                let tunnel_id = parts[1].to_string();
                                let local_addr = parts[2].to_string();

                                match TcpStream::connect(&local_addr) {
                                    Ok(local) => {
                                        let _ = local.set_nodelay(true);
                                        let _ = local
                                            .set_read_timeout(Some(Duration::from_millis(TICK_MS)));
                                        eprintln!(
                                            "[rtragent] tunnel {} -> {}",
                                            tunnel_id, local_addr
                                        );
                                        tunnels.lock().unwrap().insert(
                                            tunnel_id.clone(),
                                            TunnelState { local_stream: local },
                                        );
                                        let _ = stream
                                            .write_all(format!("TUN_OK {}\n", tunnel_id).as_bytes());
                                        let _ = stream.flush();
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "[rtragent] tunnel {} connect {} failed: {}",
                                            tunnel_id, local_addr, e
                                        );
                                        let _ = stream.write_all(
                                            format!("TUN_CLOSE {}\n", tunnel_id).as_bytes(),
                                        );
                                        let _ = stream.flush();
                                    }
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
                                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
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

        flush_tunnels(stream, &tunnels);
    }
}

fn flush_tunnels(
    stream: &mut TcpStream,
    tunnels: &Arc<Mutex<HashMap<String, TunnelState>>>,
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
        let _ = stream.write_all(&frame);
    }

    for tid in to_close {
        let _ = stream.write_all(format!("TUN_CLOSE {}\n", tid).as_bytes());
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