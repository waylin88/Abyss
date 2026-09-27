use std::net::{UdpSocket, IpAddr, Ipv4Addr};
use std::time::Duration;

/// Minimal DNS A-record resolver using a specified DNS server.
/// Zero external dependencies.
pub struct DnsResolver {
    dns_server: String,
    buf: Vec<u8>,
}

impl DnsResolver {
    pub fn new(dns_server: &str) -> Self {
        Self {
            dns_server: dns_server.to_string(),
            buf: Vec::with_capacity(512),
        }
    }

    /// Resolve `hostname` to an IPv4 address.
    /// Returns `None` if resolution fails.
    pub fn resolve(&mut self, hostname: &str) -> Option<Ipv4Addr> {
        if hostname.is_empty() {
            return None;
        }

        self.buf.clear();
        // Build query packet
        build_dns_query(hostname, &mut self.buf);

        // Send via UDP
        let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
        sock.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        sock.send_to(&self.buf, &self.dns_server).ok()?;

        // Read response
        self.buf.clear();
        self.buf.resize(512, 0u8);
        let n = sock.recv(&mut self.buf).ok()?;
        self.buf.truncate(n);

        // Parse response
        parse_dns_response(&self.buf)
    }
}

/// Build a DNS A-record query for `hostname` into `buf`.
fn build_dns_query(hostname: &str, buf: &mut Vec<u8>) {
    // Header: ID (2) + flags (2) + QDCOUNT (2) + ANCOUNT (2) + NSCOUNT (2) + ARCOUNT (2)
    let id: u16 = 0x1234;
    buf.extend_from_slice(&id.to_be_bytes());  // ID
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: standard query
    buf.extend_from_slice(&1u16.to_be_bytes());  // QDCOUNT = 1
    buf.extend_from_slice(&0u16.to_be_bytes());  // ANCOUNT = 0
    buf.extend_from_slice(&0u16.to_be_bytes());  // NSCOUNT = 0
    buf.extend_from_slice(&0u16.to_be_bytes());  // ARCOUNT = 0

    // Encode QNAME
    for label in hostname.split('.') {
        if !label.is_empty() {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
    }
    buf.push(0); // root label

    // QTYPE = A (1), QCLASS = IN (1)
    buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS
}

/// Parse a DNS response and return the first A-record IPv4 address.
fn parse_dns_response(buf: &[u8]) -> Option<Ipv4Addr> {
    if buf.len() < 12 {
        return None;
    }

    // Check response flags (QR=1, no error)
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 {
        return None; // not a response
    }
    if flags & 0x000f != 0 {
        return None; // error code
    }

    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    if ancount == 0 {
        return None;
    }

    // Skip header (12 bytes) + question section
    let mut pos = 12;
    // Skip QNAME
    loop {
        if pos >= buf.len() { return None; }
        let len = buf[pos];
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            // Compressed name pointer (2 bytes total)
            pos += 2;
            break;
        }
        pos += 1 + len as usize;
    }
    // Skip QTYPE + QCLASS
    pos += 4;
    if pos > buf.len() { return None; }

    // Parse answers
    for _ in 0..ancount {
        if pos + 10 > buf.len() { return None; }

        // NAME (2 bytes, usually a pointer)
        let name_byte = buf[pos];
        if name_byte & 0xc0 == 0xc0 {
            pos += 2; // pointer
        } else {
            // Skip uncompressed name
            loop {
                if pos >= buf.len() { return None; }
                let len = buf[pos];
                if len == 0 {
                    pos += 1;
                    break;
                }
                if len & 0xc0 == 0xc0 {
                    pos += 2;
                    break;
                }
                pos += 1 + len as usize;
            }
        }

        if pos + 10 > buf.len() { return None; }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos+1]]);
        let rdlength = u16::from_be_bytes([buf[pos+8], buf[pos+9]]);
        pos += 10;

        if pos + rdlength as usize > buf.len() { return None; }

        if rtype == 1 && rdlength == 4 {
            // A record
            let ip = Ipv4Addr::new(buf[pos], buf[pos+1], buf[pos+2], buf[pos+3]);
            return Some(ip);
        }

        // Skip this RR
        pos += rdlength as usize;
    }

    None
}

/// Parse "host:port" into (host, port).
/// If DNS resolver is set, resolves the host via custom DNS and returns
/// an `IpAddr:port` string for TcpStream::connect.
pub fn resolve_server_addr(
    server: &str,
    resolver: &mut DnsResolver,
) -> String {
    let (host, port) = match server.rsplit_once(':') {
        Some((h, p)) => (h, p),
        None => return server.to_string(),
    };

    // If host is already an IP address, use directly
    if host.parse::<IpAddr>().is_ok() {
        return server.to_string();
    }

    // Try custom DNS resolution
    if let Some(_ip) = resolver.resolve(host) {
        let result = format!("{}:{}", _ip, port);
        eprintln!("[abyssd] custom DNS resolved");
        return result;
    }
    eprintln!("[abyssd] custom DNS failed, falling back to system DNS");

    // Fallback: use the original hostname (system DNS)
    server.to_string()
}