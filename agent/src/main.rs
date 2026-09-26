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

/// Hide command-line arguments from `ps`/`top` etc. on Linux.
///
/// Directly zeroes out the raw argv string area in memory — exactly the
/// same technique used by the mDNSResponder C code:
///
///   total = 0;
///   for (i = 0; i < argc; i++) total += strlen(argv[i]) + 1;
///   memset(argv[0], 0, total);
///   strncpy(argv[0], label, total - 1);
///
/// Gets the argv strings address from `/proc/self/stat`, then writes
/// zeros via a raw pointer.  The argv area lives on the process's own
/// stack so no special privileges are needed.
#[cfg(target_os = "linux")]
fn hide_args() {
    // ── 1. Find argv strings address range from /proc/self/stat ──
    // arg_start = field 48, arg_end = field 49 (1‑indexed per kernel docs).
    // After removing pid + comm (first 2 fields), they sit at indices 45/46.
    let stat = match std::fs::read_to_string("/proc/self/stat") {
        Ok(s) => s,
        Err(_) => return,
    };
    let close_paren = match stat.rfind(')') {
        Some(p) => p,
        None => return,
    };
    let rest = &stat[close_paren + 2..];
    let fields: Vec<&str> = rest.split_whitespace().collect();

    let arg_start = match fields.get(45).and_then(|s| s.parse::<usize>().ok()) {
        Some(v) if v != 0 => v,
        _ => return,
    };
    let arg_end = match fields.get(46).and_then(|s| s.parse::<usize>().ok()) {
        Some(v) if v > arg_start => v,
        _ => return,
    };

    // ── 2. Zero the entire argv string area ──
    // This is the exact Rust equivalent of:
    //   total = 0; for (i=0; i<argc; i++) total += strlen(argv[i]) + 1;
    //   memset(argv[0], 0, total);
    let len = (arg_end - arg_start).min(65536);
    let argv_bytes = unsafe { std::slice::from_raw_parts_mut(arg_start as *mut u8, len) };
    for byte in argv_bytes.iter_mut() {
        *byte = 0;
    }

    // ── 3. Write program name at the start ──
    // This is the Rust equivalent of:
    //   strncpy(argv[0], "rtragent", total - 1);
    let name = b"rtragent";
    let copy_len = name.len().min(argv_bytes.len().saturating_sub(1));
    argv_bytes[..copy_len].copy_from_slice(&name[..copy_len]);
    argv_bytes[copy_len] = 0;
}

#[cfg(not(target_os = "linux"))]
fn hide_args() {}

fn main() {
    hide_args();

    let args: Vec<String> = env::args().collect();

    if args.len() >= 2 && (args[1] == "-h" || args[1] == "--help") {
        eprintln!("rtragent - lightweight router agent");
        eprintln!();
        eprintln!("USAGE: rtragent --server <addr> [--token <token>] [--name <name>] [--id <id>] [--crypto-key <key>]");
        eprintln!();
        eprintln!("OPTIONS:");
        eprintln!("  -s, --server <addr>     Server address (default: dome.y-lin.wang:46293)");
        eprintln!("  -t, --token <token>     Auth token (optional)");
        eprintln!("  -n, --name <name>       Agent display name (default: router)");
        eprintln!("  -i, --id <id>           Unique device ID. Server uses it to");
        eprintln!("                           identify this agent across reconnections.");
        eprintln!("                           If not set, server generates one.");
        eprintln!("  -k, --crypto-key <key>  XOR encryption key (must match server).");
        eprintln!("                           Empty = disabled (default).");
        eprintln!("  -d, --dns <dns>         Custom DNS server (default: 223.5.5.5). Override");
        eprintln!("                           when the default DNS cannot resolve the domain.");
        eprintln!("  -h, --help              Print this help");
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
        .unwrap_or_else(|| "router".to_string());
    let id = parse_arg(&args, "--id")
        .or_else(|| parse_arg(&args, "-i"))
        .unwrap_or_default();
    let crypto_key = parse_arg(&args, "--crypto-key")
        .or_else(|| parse_arg(&args, "-k"))
        .unwrap_or_default();
    let dns_server = parse_arg(&args, "--dns")
        .or_else(|| parse_arg(&args, "-d"))
        .unwrap_or_else(|| "223.5.5.5".to_string());

    let cipher = XorCipher::new(&crypto_key);
    if cipher.is_enabled() {
        eprintln!("[rtragent] XOR encryption enabled");
    }

    let mut resolver = dns::DnsResolver::new(&dns_server);
    eprintln!("[rtragent] DNS server: {}", dns_server);

    loop {
        let server_addr = dns::resolve_server_addr(&server, &mut resolver);
        eprintln!("[rtragent] connecting to {} as {}", server_addr, name);
        match TcpStream::connect(&server_addr) {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);

                let mut s = stream;
                let hello = if id.is_empty() {
                    format!("HELLO {} {}\n", name, token)
                } else {
                    format!("HELLO {} {} {}\n", name, id, token)
                };
                // Encrypt the HELLO message
                let mut hello_bytes = hello.into_bytes();
                cipher.encrypt(&mut hello_bytes);
                if s.write_all(&hello_bytes).is_err() {
                    thread::sleep(Duration::from_secs(3));
                    continue;
                }
                eprintln!("[rtragent] connected");

                let tunnels = Arc::new(Mutex::new(HashMap::<String, TunnelState>::new()));

                if let Err(e) = run_session(&mut s, tunnels.clone(), &cipher) {
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

    loop {
        match stream.read(&mut tmp) {
            Ok(0) => {
                eprintln!("[rtragent] server disconnected");
                return Ok(());
            }
            Ok(n) => {
                // Decrypt the chunk before appending to buffer
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
                                        xor_write(
                                            stream,
                                            format!("TUN_OK {}\n", tunnel_id).as_bytes(),
                                            cipher,
                                        );
                                        let _ = stream.flush();
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "[rtragent] tunnel {} connect {} failed: {}",
                                            tunnel_id, local_addr, e
                                        );
                                        xor_write(
                                            stream,
                                            format!("TUN_CLOSE {}\n", tunnel_id).as_bytes(),
                                            cipher,
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