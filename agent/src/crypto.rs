use std::sync::atomic::{AtomicU64, Ordering};

/// 与服务端 `XorCipher` 完全一致的实现。
/// 读写计数器独立，确保加密/解密与对端同步。
/// key 为空时全部直通（明文模式）。
pub struct XorCipher {
    key: Vec<u8>,
    pub read_pos: AtomicU64,
    pub write_pos: AtomicU64,
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