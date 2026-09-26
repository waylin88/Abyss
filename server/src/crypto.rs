use std::sync::atomic::{AtomicU64, Ordering};

/// 简单的 XOR 流加密。
///
/// 读写使用独立的位置计数器，双向密钥流互不影响。
/// XOR 是对称的，加密和解密是同一操作。
///
/// 当 key 为空时所有操作为空操作（明文模式），向后兼容。
pub struct XorCipher {
    key: Vec<u8>,
    read_pos: AtomicU64,
    write_pos: AtomicU64,
}

impl XorCipher {
    pub fn new(key: &str) -> Self {
        Self {
            key: key.as_bytes().to_vec(),
            read_pos: AtomicU64::new(0),
            write_pos: AtomicU64::new(0),
        }
    }

    pub fn is_enabled(&self) -> bool {
        !self.key.is_empty()
    }

    /// XOR 加密 data（使用写位置计数器）。
    pub fn encrypt(&self, data: &mut [u8]) {
        if self.key.is_empty() {
            return;
        }
        let start = self.write_pos.fetch_add(data.len() as u64, Ordering::Relaxed);
        let key_len = self.key.len();
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= self.key[((start as usize) + i) % key_len];
        }
    }

    /// XOR 解密 data（使用读位置计数器）。
    pub fn decrypt(&self, data: &mut [u8]) {
        if self.key.is_empty() {
            return;
        }
        let start = self.read_pos.fetch_add(data.len() as u64, Ordering::Relaxed);
        let key_len = self.key.len();
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= self.key[((start as usize) + i) % key_len];
        }
    }
}