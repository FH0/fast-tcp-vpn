use std::fmt;

/// 加密模块错误类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// 密钥长度无效
    InvalidKeyLength { expected: usize, actual: usize },
    /// Nonce 长度无效
    InvalidNonceLength { expected: usize, actual: usize },
    /// 加密失败
    EncryptionFailed(String),
    /// 解密失败
    DecryptionFailed(String),
    /// 认证失败 (密文被篡改)
    AuthenticationFailed,
    /// 数据太短
    DataTooShort { minimum: usize, actual: usize },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidKeyLength { expected, actual } => {
                write!(f, "Invalid key length: expected {}, got {}", expected, actual)
            }
            CryptoError::InvalidNonceLength { expected, actual } => {
                write!(f, "Invalid nonce length: expected {}, got {}", expected, actual)
            }
            CryptoError::EncryptionFailed(msg) => {
                write!(f, "Encryption failed: {}", msg)
            }
            CryptoError::DecryptionFailed(msg) => {
                write!(f, "Decryption failed: {}", msg)
            }
            CryptoError::AuthenticationFailed => {
                write!(f, "Authentication failed: ciphertext may have been tampered")
            }
            CryptoError::DataTooShort { minimum, actual } => {
                write!(f, "Data too short: minimum {} bytes, got {}", minimum, actual)
            }
        }
    }
}

impl std::error::Error for CryptoError {}
