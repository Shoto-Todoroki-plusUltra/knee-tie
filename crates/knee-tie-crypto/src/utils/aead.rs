//! Shared ChaCha20-Poly1305 AEAD helpers.
//!
//! Used by epoch::key (encrypting post content under an epoch key),
//! epoch::seal (sealing epoch keys for specific members), and
//! identity::store (encrypting the local identity file).
//!
//! Follows the same GenericArray-based construction already proven to
//! compile in utils/sprp.rs (for AES), rather than the `Key`/`Nonce`
//! type-alias sugar some chacha20poly1305 usage examples show — that
//! sugar's reference-vs-owned usage is inconsistent across different
//! published examples, whereas the GenericArray pattern below is
//! already confirmed working in this exact codebase.

use chacha20poly1305::{ChaCha20Poly1305, aead::{Aead, KeyInit}};
use chacha20poly1305::aead::generic_array::GenericArray;
use crate::error::{Result, KneeTieError};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

/// Encrypt `plaintext` with ChaCha20-Poly1305 under `key`, using a
/// caller-supplied 12-byte `nonce`.
///
/// CRITICAL: the (key, nonce) pair must never be reused for two
/// different plaintexts. Every caller in this crate generates a fresh
/// random nonce per call via `random_nonce()` below.
pub fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let key_arr   = GenericArray::from_slice(key);
    let cipher    = ChaCha20Poly1305::new(key_arr);
    let nonce_arr = GenericArray::from_slice(nonce);
    cipher.encrypt(nonce_arr, plaintext)
        .map_err(|_| KneeTieError::CryptoError("ChaCha20-Poly1305 encryption failed".into()))
}

/// Decrypt `ciphertext` (which must include the Poly1305 tag, as
/// produced by `encrypt` above) with ChaCha20-Poly1305 under `key`
/// and `nonce`.
///
/// Returns an error if the authentication tag does not verify (wrong
/// key, wrong nonce, or tampered ciphertext) — the error deliberately
/// carries no detail about which, per AEAD design best practice.
pub fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let key_arr   = GenericArray::from_slice(key);
    let cipher    = ChaCha20Poly1305::new(key_arr);
    let nonce_arr = GenericArray::from_slice(nonce);
    cipher.decrypt(nonce_arr, ciphertext)
        .map_err(|_| KneeTieError::CryptoError(
            "ChaCha20-Poly1305 decryption failed (wrong key/nonce or tampered ciphertext)".into()
        ))
}

/// Generate a fresh random 12-byte nonce.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    use rand::RngCore;
    let mut n = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_roundtrips() {
        let key = [7u8; KEY_LEN];
        let nonce = random_nonce();
        let plaintext = b"a message to protect";

        let ct = encrypt(&key, &nonce, plaintext).unwrap();
        let pt = decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn ciphertext_differs_from_plaintext() {
        let key = [1u8; KEY_LEN];
        let nonce = random_nonce();
        let plaintext = b"visible only to the right key";
        let ct = encrypt(&key, &nonce, plaintext).unwrap();
        assert_ne!(ct, plaintext.to_vec());
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key1 = [1u8; KEY_LEN];
        let key2 = [2u8; KEY_LEN];
        let nonce = random_nonce();
        let ct = encrypt(&key1, &nonce, b"secret").unwrap();
        assert!(decrypt(&key2, &nonce, &ct).is_err());
    }

    #[test]
    fn wrong_nonce_fails_decryption() {
        let key = [1u8; KEY_LEN];
        let nonce1 = random_nonce();
        let mut nonce2 = nonce1;
        nonce2[0] ^= 0xFF;
        let ct = encrypt(&key, &nonce1, b"secret").unwrap();
        assert!(decrypt(&key, &nonce2, &ct).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_decryption() {
        let key = [1u8; KEY_LEN];
        let nonce = random_nonce();
        let mut ct = encrypt(&key, &nonce, b"secret message").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        assert!(decrypt(&key, &nonce, &ct).is_err());
    }

    #[test]
    fn nonces_are_random() {
        let n1 = random_nonce();
        let n2 = random_nonce();
        assert_ne!(n1, n2);
    }
}
