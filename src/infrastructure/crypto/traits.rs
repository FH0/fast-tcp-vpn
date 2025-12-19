use super::CryptoError;

/// 加密器 trait
///
/// 提供对称加密/解密能力，支持 AEAD (Authenticated Encryption with Associated Data)
pub trait Encryptor: Send + Sync {
    /// 加密数据
    ///
    /// # Arguments
    /// * `nonce` - 随机数/初始化向量，每次加密必须唯一
    /// * `plaintext` - 明文数据
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - 密文 (包含认证标签)
    /// * `Err(CryptoError)` - 加密失败
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// 解密数据
    ///
    /// # Arguments
    /// * `nonce` - 加密时使用的随机数
    /// * `ciphertext` - 密文 (包含认证标签)
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - 明文数据
    /// * `Err(CryptoError)` - 解密失败或认证失败
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// 获取 nonce 长度
    fn nonce_len(&self) -> usize;

    /// 获取认证标签长度
    fn tag_len(&self) -> usize;
}
