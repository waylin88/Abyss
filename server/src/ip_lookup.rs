use std::path::Path;

/// Pure Rust IP geolocation lookup using QQWry (纯真) database.
pub struct IpLookup {
    /// Path to qqwry.dat, wrapped in Option so we can mutably borrow
    db_path: Option<String>,
}

impl IpLookup {
    /// Load qqwry.dat from `data_dir/qqwry.dat`.
    /// Returns a lookup instance; if the file does not exist,
    /// all lookups will return `None`.
    pub fn new(data_dir: &Path) -> Self {
        let path = data_dir.join("qqwry.dat");
        if !path.exists() {
            println!(
                "[ip-lookup] qqwry.dat not found at {:?}, IP lookup disabled",
                path
            );
            println!("[ip-lookup] 提示：将纯真IP库 qqwry.dat 放入 data/ 目录后重启可查询IP归属地");
            return Self { db_path: None };
        }

        let p = path.to_string_lossy().to_string();
        println!("[ip-lookup] qqwry.dat found at {:?}, IP lookup enabled", path);
        Self { db_path: Some(p) }
    }

    /// Look up the geographic location of an IPv4 address string.
    /// Returns a human-readable string like "中国 广东省 深圳市 电信",
    /// or `None` if the database is unavailable or the IP is not found.
    pub fn lookup(&self, ip: &str) -> Option<String> {
        let path = self.db_path.as_ref()?;
        // The QQWry API opens the file on every call
        let mut wry = qqwry::qqwry::QQWry::from(path.clone());
        let loc = wry.read_ip_location(ip)?;
        let mut parts = Vec::new();
        if !loc.country.is_empty() {
            parts.push(loc.country.as_str());
        }
        if !loc.area.is_empty() {
            parts.push(loc.area.as_str());
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" "))
        }
    }
}