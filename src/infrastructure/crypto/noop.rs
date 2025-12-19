use super::{CryptoError, Encryptor};

/// Noop (无操作) 加密器
///
/// 不进行任何加密，直接返回原始数据
/// 仅用于调试和测试目的，**不要在生产环境使用**
pub struct NoopEncryptor;

impl NoopEncryptor {
    /// 创建新的 Noop 加密器
    pub fn new() -> Self {
        Self
    }
}

impl Default for NoopEncryptor {
    fn default() -> Self {
        Self::new()
    }
}

impl Encryptor for NoopEncryptor {
    fn encrypt(&self, _nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // 直接返回明文副本
        Ok(plaintext.to_vec())
    }

    fn decrypt(&self, _nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // 直接返回密文副本 (实际上就是明文)
        Ok(ciphertext.to_vec())
    }

    fn nonce_len(&self) -> usize {
        0 // Noop 不需要 nonce
    }

    fn tag_len(&self) -> usize {
        0 // Noop 不添加认证标签
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop_encrypt_returns_plaintext() {
        let encryptor = NoopEncryptor::new();
        let plaintext = b"Hello, World!";
        let nonce = [0u8; 12];

        let ciphertext = encryptor.encrypt(&nonce, plaintext).unwrap();
        assert_eq!(ciphertext, plaintext);
    }

    #[test]
    fn test_noop_decrypt_returns_ciphertext() {
        let encryptor = NoopEncryptor::new();
        let data = b"Some data";
        let nonce = [0u8; 12];

        let decrypted = encryptor.decrypt(&nonce, data).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_noop_roundtrip() {
        let encryptor = NoopEncryptor::new();
        let plaintext = b"Test message";
        let nonce = [];

        let ciphertext = encryptor.encrypt(&nonce, plaintext).unwrap();
        let decrypted = encryptor.decrypt(&nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_noop_empty_data() {
        let encryptor = NoopEncryptor::new();
        let plaintext = b"";
        let nonce = [];

        let ciphertext = encryptor.encrypt(&nonce, plaintext).unwrap();
        assert!(ciphertext.is_empty());

        let decrypted = encryptor.decrypt(&nonce, &ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_noop_lengths() {
        let encryptor = NoopEncryptor::new();
        assert_eq!(encryptor.nonce_len(), 0);
        assert_eq!(encryptor.tag_len(), 0);
    }

    #[test]
    fn test_noop_default() {
        let encryptor = NoopEncryptor::default();
        let plaintext = b"test";
        let ciphertext = encryptor.encrypt(&[], plaintext).unwrap();
        assert_eq!(ciphertext, plaintext);
    }
}
