use super::{CryptoError, Encryptor};

/// ChaCha20-Poly1305 密钥长度 (256 bits)
pub const KEY_LEN: usize = 32;
/// ChaCha20-Poly1305 Nonce 长度 (96 bits)
pub const NONCE_LEN: usize = 12;
/// Poly1305 认证标签长度 (128 bits)
pub const TAG_LEN: usize = 16;

/// ChaCha20-Poly1305 AEAD 加密器
///
/// 使用 ChaCha20 流密码和 Poly1305 消息认证码
/// 提供认证加密 (AEAD)，可检测密文篡改
pub struct ChaCha20Poly1305 {
    key: [u8; KEY_LEN],
}

impl ChaCha20Poly1305 {
    /// 创建新的加密器
    ///
    /// # Arguments
    /// * `key` - 256-bit 密钥
    ///
    /// # Returns
    /// * `Ok(Self)` - 加密器实例
    /// * `Err(CryptoError)` - 密钥长度无效
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: KEY_LEN,
                actual: key.len(),
            });
        }
        let mut key_arr = [0u8; KEY_LEN];
        key_arr.copy_from_slice(key);
        Ok(Self { key: key_arr })
    }

    /// ChaCha20 quarter round
    #[inline]
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);

        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }

    /// ChaCha20 block function
    fn chacha20_block(&self, nonce: &[u8], counter: u32) -> [u8; 64] {
        // Constants "expand 32-byte k"
        let mut state: [u32; 16] = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            u32::from_le_bytes([self.key[0], self.key[1], self.key[2], self.key[3]]),
            u32::from_le_bytes([self.key[4], self.key[5], self.key[6], self.key[7]]),
            u32::from_le_bytes([self.key[8], self.key[9], self.key[10], self.key[11]]),
            u32::from_le_bytes([self.key[12], self.key[13], self.key[14], self.key[15]]),
            u32::from_le_bytes([self.key[16], self.key[17], self.key[18], self.key[19]]),
            u32::from_le_bytes([self.key[20], self.key[21], self.key[22], self.key[23]]),
            u32::from_le_bytes([self.key[24], self.key[25], self.key[26], self.key[27]]),
            u32::from_le_bytes([self.key[28], self.key[29], self.key[30], self.key[31]]),
            counter,
            u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
            u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
            u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
        ];

        let initial_state = state;

        // 20 rounds (10 double rounds)
        for _ in 0..10 {
            // Column rounds
            Self::quarter_round(&mut state, 0, 4, 8, 12);
            Self::quarter_round(&mut state, 1, 5, 9, 13);
            Self::quarter_round(&mut state, 2, 6, 10, 14);
            Self::quarter_round(&mut state, 3, 7, 11, 15);
            // Diagonal rounds
            Self::quarter_round(&mut state, 0, 5, 10, 15);
            Self::quarter_round(&mut state, 1, 6, 11, 12);
            Self::quarter_round(&mut state, 2, 7, 8, 13);
            Self::quarter_round(&mut state, 3, 4, 9, 14);
        }

        // Add initial state
        for i in 0..16 {
            state[i] = state[i].wrapping_add(initial_state[i]);
        }

        // Serialize to bytes
        let mut output = [0u8; 64];
        for (i, word) in state.iter().enumerate() {
            output[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        output
    }

    /// ChaCha20 encryption/decryption (XOR with keystream)
    fn chacha20_encrypt(&self, nonce: &[u8], data: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(data.len());
        let mut counter = 1u32; // Counter starts at 1 for encryption

        for chunk in data.chunks(64) {
            let keystream = self.chacha20_block(nonce, counter);
            for (i, &byte) in chunk.iter().enumerate() {
                output.push(byte ^ keystream[i]);
            }
            counter = counter.wrapping_add(1);
        }
        output
    }

    /// Poly1305 MAC using 130-bit arithmetic
    fn poly1305_mac(&self, nonce: &[u8], data: &[u8]) -> [u8; TAG_LEN] {
        // Generate Poly1305 key from ChaCha20 block with counter 0
        let poly_key_block = self.chacha20_block(nonce, 0);
        let r = Self::clamp_r(&poly_key_block[0..16]);
        let s = Self::le_bytes_to_num(&poly_key_block[16..32]);

        // Process data in 16-byte blocks
        // Using [u64; 3] to represent 130-bit numbers (accumulator)
        let mut acc = [0u64; 3];

        for chunk in data.chunks(16) {
            // Add chunk to accumulator
            let mut n = [0u64; 3];
            if chunk.len() >= 8 {
                n[0] = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
            } else {
                let mut tmp = [0u8; 8];
                tmp[..chunk.len()].copy_from_slice(chunk);
                n[0] = u64::from_le_bytes(tmp);
            }
            if chunk.len() > 8 {
                let remaining = &chunk[8..];
                if remaining.len() >= 8 {
                    n[1] = u64::from_le_bytes(remaining[0..8].try_into().unwrap());
                } else {
                    let mut tmp = [0u8; 8];
                    tmp[..remaining.len()].copy_from_slice(remaining);
                    n[1] = u64::from_le_bytes(tmp);
                }
            }
            // Set the high bit (2^(8*len))
            let hibit = if chunk.len() < 16 {
                1u64 << ((chunk.len() % 8) * 8)
            } else {
                1u64
            };
            if chunk.len() <= 8 {
                n[0] |= hibit << (chunk.len() * 8).min(63);
                if chunk.len() == 8 {
                    n[1] = 1;
                }
            } else if chunk.len() < 16 {
                n[1] |= hibit;
            } else {
                n[2] = 1;
            }

            // acc += n
            let (sum0, c0) = acc[0].overflowing_add(n[0]);
            let (sum1, c1) = acc[1].overflowing_add(n[1]);
            let (sum1, c1b) = sum1.overflowing_add(c0 as u64);
            let sum2 = acc[2].wrapping_add(n[2]).wrapping_add((c1 || c1b) as u64);
            acc = [sum0, sum1, sum2];

            // acc *= r (mod 2^130 - 5)
            acc = Self::poly1305_multiply(acc, r);
        }

        // acc += s
        let (sum0, c0) = acc[0].overflowing_add(s[0]);
        let (sum1, _) = acc[1].overflowing_add(s[1]);
        let sum1 = sum1.wrapping_add(c0 as u64);

        let mut tag = [0u8; TAG_LEN];
        tag[0..8].copy_from_slice(&sum0.to_le_bytes());
        tag[8..16].copy_from_slice(&sum1.to_le_bytes());
        tag
    }

    /// Multiply two 130-bit numbers mod 2^130 - 5
    fn poly1305_multiply(a: [u64; 3], r: [u64; 3]) -> [u64; 3] {
        // Full multiplication using 64-bit limbs
        // Result needs up to 260 bits, then reduce mod p

        let a0 = a[0] as u128;
        let a1 = a[1] as u128;
        let a2 = a[2] as u128;
        let r0 = r[0] as u128;
        let r1 = r[1] as u128;
        let r2 = r[2] as u128;

        // Compute product terms
        let mut d0 = a0 * r0;
        let mut d1 = a0 * r1 + a1 * r0;
        let mut d2 = a0 * r2 + a1 * r1 + a2 * r0;
        let mut d3 = a1 * r2 + a2 * r1;
        let mut d4 = a2 * r2;

        // Propagate carries
        d1 += d0 >> 64;
        d0 &= 0xFFFFFFFFFFFFFFFF;
        d2 += d1 >> 64;
        d1 &= 0xFFFFFFFFFFFFFFFF;
        d3 += d2 >> 64;
        d2 &= 0xFFFFFFFFFFFFFFFF;
        d4 += d3 >> 64;
        d3 &= 0xFFFFFFFFFFFFFFFF;

        // Now we have a 320-bit number in d4:d3:d2:d1:d0
        // Reduce mod 2^130 - 5
        // 2^130 ≡ 5 (mod p), so bits >= 130 get multiplied by 5 and added back

        // d2 has bits 128-191, we need to split at bit 130 (bit 2 of d2)
        let low130_d2 = d2 & 0x3; // bits 0-1 of d2 (bits 128-129 of result)
        let high_d2 = d2 >> 2;    // bits 2+ of d2 (bits 130+ of result)

        // high part = high_d2 + d3*2^62 + d4*2^126
        // multiply by 5 and add to low part
        let carry = high_d2 * 5;
        let carry2 = d3 * 5;
        let carry3 = d4 * 5;

        let (r0_new, c0) = (d0 as u64).overflowing_add(carry as u64);
        let (r1_new, c1) = (d1 as u64).overflowing_add((carry >> 64) as u64);
        let (r1_new, c1b) = r1_new.overflowing_add(c0 as u64);
        let (r1_new, c1c) = r1_new.overflowing_add(carry2 as u64);
        let mut r2_new = (low130_d2 as u64)
            .wrapping_add((c1 || c1b || c1c) as u64)
            .wrapping_add((carry2 >> 64) as u64)
            .wrapping_add(carry3 as u64);

        // Final reduction if needed (r2 might have bits >= 2)
        if r2_new >= 4 {
            let extra = r2_new >> 2;
            r2_new &= 0x3;
            let (r0_final, c) = r0_new.overflowing_add(extra * 5);
            let r1_final = r1_new.wrapping_add(c as u64);
            return [r0_final, r1_final, r2_new];
        }

        [r0_new, r1_new, r2_new]
    }

    /// Clamp r value for Poly1305, returns [u64; 3]
    fn clamp_r(r_bytes: &[u8]) -> [u64; 3] {
        let mut r = [0u8; 16];
        r.copy_from_slice(r_bytes);
        // Clamp r
        r[3] &= 15;
        r[7] &= 15;
        r[11] &= 15;
        r[15] &= 15;
        r[4] &= 252;
        r[8] &= 252;
        r[12] &= 252;
        Self::le_bytes_to_num(&r)
    }

    /// Convert little-endian bytes to [u64; 3] (130-bit number)
    fn le_bytes_to_num(bytes: &[u8]) -> [u64; 3] {
        let mut result = [0u64; 3];
        if bytes.len() >= 8 {
            result[0] = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        }
        if bytes.len() >= 16 {
            result[1] = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        } else if bytes.len() > 8 {
            let mut tmp = [0u8; 8];
            tmp[..bytes.len() - 8].copy_from_slice(&bytes[8..]);
            result[1] = u64::from_le_bytes(tmp);
        }
        // result[2] stays 0 for 128-bit inputs
        result
    }

    /// Poly1305 for AEAD (with AAD padding)
    fn poly1305_aead(&self, nonce: &[u8], ciphertext: &[u8]) -> [u8; TAG_LEN] {
        // For simplicity, we don't use AAD in this implementation
        // Format: pad16(ciphertext) || len(ciphertext) as u64 LE
        let mut data = Vec::with_capacity(ciphertext.len() + 24);

        // Add ciphertext with padding
        data.extend_from_slice(ciphertext);
        let pad_len = (16 - (ciphertext.len() % 16)) % 16;
        data.extend(std::iter::repeat(0u8).take(pad_len));

        // Add lengths (no AAD, so aad_len = 0)
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

        self.poly1305_mac(nonce, &data)
    }
}

impl Encryptor for ChaCha20Poly1305 {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != NONCE_LEN {
            return Err(CryptoError::InvalidNonceLength {
                expected: NONCE_LEN,
                actual: nonce.len(),
            });
        }

        // Encrypt plaintext
        let ciphertext = self.chacha20_encrypt(nonce, plaintext);

        // Generate authentication tag
        let tag = self.poly1305_aead(nonce, &ciphertext);

        // Append tag to ciphertext
        let mut result = ciphertext;
        result.extend_from_slice(&tag);
        Ok(result)
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != NONCE_LEN {
            return Err(CryptoError::InvalidNonceLength {
                expected: NONCE_LEN,
                actual: nonce.len(),
            });
        }

        if ciphertext.len() < TAG_LEN {
            return Err(CryptoError::DataTooShort {
                minimum: TAG_LEN,
                actual: ciphertext.len(),
            });
        }

        // Split ciphertext and tag
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - TAG_LEN);

        // Verify authentication tag
        let expected_tag = self.poly1305_aead(nonce, ct);
        if !Self::constant_time_compare(tag, &expected_tag) {
            return Err(CryptoError::AuthenticationFailed);
        }

        // Decrypt
        Ok(self.chacha20_encrypt(nonce, ct))
    }

    fn nonce_len(&self) -> usize {
        NONCE_LEN
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }
}

impl ChaCha20Poly1305 {
    /// Constant-time comparison to prevent timing attacks
    fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; KEY_LEN];
        let nonce = [0x24u8; NONCE_LEN];
        let plaintext = b"Hello, ChaCha20-Poly1305!";

        let encryptor = ChaCha20Poly1305::new(&key).unwrap();

        let ciphertext = encryptor.encrypt(&nonce, plaintext).unwrap();
        assert_ne!(&ciphertext[..plaintext.len()], plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_LEN);

        let decrypted = encryptor.decrypt(&nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; KEY_LEN];
        let nonce = [0x24u8; NONCE_LEN];
        let plaintext = b"";

        let encryptor = ChaCha20Poly1305::new(&key).unwrap();

        let ciphertext = encryptor.encrypt(&nonce, plaintext).unwrap();
        assert_eq!(ciphertext.len(), TAG_LEN);

        let decrypted = encryptor.decrypt(&nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_plaintext() {
        let key = [0x42u8; KEY_LEN];
        let nonce = [0x24u8; NONCE_LEN];
        let plaintext = vec![0xABu8; 1024];

        let encryptor = ChaCha20Poly1305::new(&key).unwrap();

        let ciphertext = encryptor.encrypt(&nonce, &plaintext).unwrap();
        let decrypted = encryptor.decrypt(&nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = [0x42u8; 16];
        let result = ChaCha20Poly1305::new(&short_key);
        assert!(matches!(result, Err(CryptoError::InvalidKeyLength { .. })));
    }

    #[test]
    fn test_invalid_nonce_length() {
        let key = [0x42u8; KEY_LEN];
        let short_nonce = [0x24u8; 8];
        let plaintext = b"test";

        let encryptor = ChaCha20Poly1305::new(&key).unwrap();
        let result = encryptor.encrypt(&short_nonce, plaintext);
        assert!(matches!(result, Err(CryptoError::InvalidNonceLength { .. })));
    }

    #[test]
    fn test_tampered_ciphertext() {
        let key = [0x42u8; KEY_LEN];
        let nonce = [0x24u8; NONCE_LEN];
        let plaintext = b"Secret message";

        let encryptor = ChaCha20Poly1305::new(&key).unwrap();

        let mut ciphertext = encryptor.encrypt(&nonce, plaintext).unwrap();

        // Tamper with ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        let result = encryptor.decrypt(&nonce, &ciphertext);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn test_tampered_tag() {
        let key = [0x42u8; KEY_LEN];
        let nonce = [0x24u8; NONCE_LEN];
        let plaintext = b"Secret message";

        let encryptor = ChaCha20Poly1305::new(&key).unwrap();

        let mut ciphertext = encryptor.encrypt(&nonce, plaintext).unwrap();

        // Tamper with tag (last 16 bytes)
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0xFF;

        let result = encryptor.decrypt(&nonce, &ciphertext);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let key1 = [0x42u8; KEY_LEN];
        let key2 = [0x43u8; KEY_LEN];
        let nonce = [0x24u8; NONCE_LEN];
        let plaintext = b"Same plaintext";

        let enc1 = ChaCha20Poly1305::new(&key1).unwrap();
        let enc2 = ChaCha20Poly1305::new(&key2).unwrap();

        let ct1 = enc1.encrypt(&nonce, plaintext).unwrap();
        let ct2 = enc2.encrypt(&nonce, plaintext).unwrap();

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertext() {
        let key = [0x42u8; KEY_LEN];
        let nonce1 = [0x24u8; NONCE_LEN];
        let nonce2 = [0x25u8; NONCE_LEN];
        let plaintext = b"Same plaintext";

        let encryptor = ChaCha20Poly1305::new(&key).unwrap();

        let ct1 = encryptor.encrypt(&nonce1, plaintext).unwrap();
        let ct2 = encryptor.encrypt(&nonce2, plaintext).unwrap();

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_ciphertext_too_short() {
        let key = [0x42u8; KEY_LEN];
        let nonce = [0x24u8; NONCE_LEN];
        let short_ciphertext = [0u8; 10]; // Less than TAG_LEN

        let encryptor = ChaCha20Poly1305::new(&key).unwrap();
        let result = encryptor.decrypt(&nonce, &short_ciphertext);
        assert!(matches!(result, Err(CryptoError::DataTooShort { .. })));
    }
}
