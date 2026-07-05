//! Epoch keys — content encryption keys that rotate on member revocation.
//!
//! Design ("Solution 3" from the project's architecture discussion —
//! this is Knee Tie's own construction, not from either paper):
//!
//!   - A community starts at epoch 0 with a fresh random key.
//!   - New epochs are created ONLY on revocation events (not on every
//!     join), keeping the number of epochs proportional to moderation
//!     activity rather than membership growth.
//!   - Each post is tagged with the epoch active when it was created,
//!     and encrypted with that epoch's key.
//!   - A member's access to past epochs, once granted, is never revoked
//!     retroactively — only ACCESS TO FUTURE epochs is cut off on
//!     revocation. This is a deliberate, documented tradeoff: it avoids
//!     the "all history becomes unreadable after any membership change"
//!     problem of naive single-shared-key rotation, at the cost of a
//!     revoked member retaining whatever they could already read.

use zeroize::ZeroizeOnDrop;
use rand::RngCore;
use crate::utils::aead::{self, KEY_LEN, NONCE_LEN};
use crate::error::Result;

/// A single epoch's symmetric content-encryption key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct EpochKey {
    pub epoch_number: u64,
    pub key: [u8; KEY_LEN],
}

impl EpochKey {
    /// Generate a fresh, random epoch key for the given epoch number.
    pub fn generate(epoch_number: u64) -> Self {
        let mut key = [0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut key);
        EpochKey { epoch_number, key }
    }
}

/// Encrypted post content, tagged with the epoch used to encrypt it.
pub struct EncryptedContent {
    pub epoch_number: u64,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Encrypt post content under a specific epoch key.
pub fn encrypt_content(epoch_key: &EpochKey, plaintext: &[u8]) -> Result<EncryptedContent> {
    let nonce = aead::random_nonce();
    let ciphertext = aead::encrypt(&epoch_key.key, &nonce, plaintext)?;
    Ok(EncryptedContent { epoch_number: epoch_key.epoch_number, nonce, ciphertext })
}

/// Decrypt post content given the matching epoch key.
///
/// Caller is responsible for looking up the correct `EpochKey` by
/// `content.epoch_number` (e.g. via `MemberEpochKeyRing::get`) before
/// calling this.
pub fn decrypt_content(epoch_key: &EpochKey, content: &EncryptedContent) -> Result<Vec<u8>> {
    aead::decrypt(&epoch_key.key, &content.nonce, &content.ciphertext)
}

/// The manager-side, plaintext history of all epoch keys a community
/// has ever had. Only the manager (or a threshold of seniors, per the
/// project's governance design) holds this in full.
pub struct EpochHistory {
    epochs: Vec<EpochKey>,
}

impl EpochHistory {
    /// Start a new community at epoch 0.
    pub fn new() -> Self {
        EpochHistory { epochs: vec![EpochKey::generate(0)] }
    }

    pub fn current_epoch_number(&self) -> u64 {
        self.epochs.len() as u64 - 1
    }

    pub fn current_epoch(&self) -> &EpochKey {
        self.epochs.last().expect("EpochHistory is never empty")
    }

    /// Look up a specific past epoch's key.
    pub fn get(&self, epoch_number: u64) -> Option<&EpochKey> {
        self.epochs.get(epoch_number as usize)
    }

    /// All epochs from `start` (inclusive) to the current epoch.
    /// Used for the "FullHistory" new-member access policy.
    pub fn epochs_from(&self, start: u64) -> &[EpochKey] {
        let start = (start as usize).min(self.epochs.len());
        &self.epochs[start..]
    }

    /// Begin a new epoch (called on member revocation). Returns the
    /// newly created epoch key, which the caller must then seal and
    /// distribute to every remaining active member.
    pub fn rotate(&mut self) -> &EpochKey {
        let next = self.epochs.len() as u64;
        self.epochs.push(EpochKey::generate(next));
        self.epochs.last().unwrap()
    }
}

impl Default for EpochHistory {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_history_starts_at_epoch_0() {
        let h = EpochHistory::new();
        assert_eq!(h.current_epoch_number(), 0);
        assert_eq!(h.current_epoch().epoch_number, 0);
    }

    #[test]
    fn rotate_increments_epoch_number() {
        let mut h = EpochHistory::new();
        h.rotate();
        assert_eq!(h.current_epoch_number(), 1);
        h.rotate();
        assert_eq!(h.current_epoch_number(), 2);
    }

    #[test]
    fn rotate_produces_a_different_key() {
        let mut h = EpochHistory::new();
        let k0 = h.get(0).unwrap().key;
        h.rotate();
        let k1 = h.get(1).unwrap().key;
        assert_ne!(k0, k1);
    }

    #[test]
    fn epochs_from_zero_returns_full_history() {
        let mut h = EpochHistory::new();
        h.rotate();
        h.rotate();
        assert_eq!(h.epochs_from(0).len(), 3);
    }

    #[test]
    fn epochs_from_current_returns_one() {
        let mut h = EpochHistory::new();
        h.rotate();
        h.rotate();
        let current = h.current_epoch_number();
        assert_eq!(h.epochs_from(current).len(), 1);
    }

    #[test]
    fn encrypt_decrypt_content_roundtrips() {
        let key = EpochKey::generate(0);
        let plaintext = b"a post visible to this epoch's members";
        let encrypted = encrypt_content(&key, plaintext).unwrap();
        assert_eq!(encrypted.epoch_number, 0);
        let decrypted = decrypt_content(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_epoch_key_fails_to_decrypt() {
        let key0 = EpochKey::generate(0);
        let key1 = EpochKey::generate(1);
        let encrypted = encrypt_content(&key0, b"secret post").unwrap();
        assert!(decrypt_content(&key1, &encrypted).is_err());
    }
}
