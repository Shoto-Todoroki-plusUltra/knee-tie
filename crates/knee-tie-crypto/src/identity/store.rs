//! Encrypted local storage building block for identity material.
//!
//! Provides password-based key derivation (Argon2id) plus symmetric
//! encryption/decryption of an arbitrary serialized blob. Deliberately
//! does NOT decide on-disk file format, CLI prompting, or what exactly
//! gets serialized inside the blob — those are Phase 4 (TUI client)
//! concerns. This module is the reusable cryptographic primitive any
//! client implementation builds on.

use argon2::Argon2;
use rand::RngCore;
use crate::utils::aead::{self, KEY_LEN, NONCE_LEN};
use crate::error::{Result, KneeTieError};

/// Recommended salt length in bytes for the password-derived key.
pub const SALT_LEN: usize = 16;

/// An encrypted blob as it would be written to disk: the salt used
/// for key derivation, the nonce used for encryption, and the
/// ciphertext itself. All three fields are stored together in the
/// clear — none of this is secret on its own (only the passphrase and
/// the derived key are).
pub struct EncryptedBlob {
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Derive a 32-byte symmetric key from a passphrase and salt using
/// Argon2id with the crate's default (OWASP-recommended) parameters.
fn derive_key(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| KneeTieError::CryptoError("Argon2 key derivation failed".into()))?;
    Ok(key)
}

/// Encrypt `plaintext` (e.g. a serialized identity record) under a
/// freshly-generated random salt, deriving the encryption key from
/// `passphrase` via Argon2id.
pub fn seal(passphrase: &[u8], plaintext: &[u8]) -> Result<EncryptedBlob> {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_key(passphrase, &salt)?;
    let nonce = aead::random_nonce();
    let ciphertext = aead::encrypt(&key, &nonce, plaintext)?;

    Ok(EncryptedBlob { salt, nonce, ciphertext })
}

/// Decrypt a blob previously produced by `seal`, given the same
/// passphrase. Fails (without distinguishing why, per AEAD best
/// practice) if the passphrase is wrong or the blob was tampered with.
pub fn open(passphrase: &[u8], blob: &EncryptedBlob) -> Result<Vec<u8>> {
    let key = derive_key(passphrase, &blob.salt)?;
    aead::decrypt(&key, &blob.nonce, &blob.ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_then_open_roundtrips() {
        let passphrase = b"a reasonably strong passphrase";
        let plaintext = b"serialized identity data goes here";
        let blob = seal(passphrase, plaintext).unwrap();
        let recovered = open(passphrase, &blob).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrong_passphrase_fails_to_open() {
        let blob = seal(b"correct passphrase", b"secret data").unwrap();
        assert!(open(b"wrong passphrase", &blob).is_err());
    }

    #[test]
    fn each_seal_uses_a_fresh_salt() {
        let blob1 = seal(b"same passphrase", b"same plaintext").unwrap();
        let blob2 = seal(b"same passphrase", b"same plaintext").unwrap();
        assert_ne!(blob1.salt, blob2.salt);
        // Different salts (and nonces) mean ciphertexts differ even
        // for identical passphrase+plaintext.
        assert_ne!(blob1.ciphertext, blob2.ciphertext);
    }

    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let passphrase = b"passphrase";
        let mut blob = seal(passphrase, b"important data").unwrap();
        let last = blob.ciphertext.len() - 1;
        blob.ciphertext[last] ^= 0xFF;
        assert!(open(passphrase, &blob).is_err());
    }
}
