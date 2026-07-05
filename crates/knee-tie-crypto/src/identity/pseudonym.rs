//! Pseudonym signing keys — the per-post authorship layer.
//!
//! This is deliberately SEPARATE from DGMT (crate::dgmt). DGMT proves,
//! once at registration, "this pseudonym belongs to a legitimate group
//! member" (post-quantum, but expensive — ~5.75 KB per signature). This
//! module provides the lightweight signature used on EVERY post
//! afterward: Ed25519, ~64 bytes, microseconds to verify. See the
//! project's architecture notes: "DGMT once at join; Ed25519 per post."
//!
//! Ed25519 is a mature, widely-audited construction (unlike DGMT and
//! Elligator-K1, which are recent research constructions this project
//! implements directly from the papers) — so this module wraps the
//! `ed25519-dalek` crate rather than hand-rolling anything.

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::RngCore;
use crate::error::{Result, KneeTieError};

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// A pseudonym's signing keypair.
///
/// Deliberately does not derive or implement Debug — printing a
/// keypair's Debug representation must never be possible even by
/// accident. Callers who need to log something use
/// `.public_key_bytes()` explicitly instead.
pub struct PseudonymKeypair {
    signing_key: SigningKey,
}

impl PseudonymKeypair {
    /// Generate a fresh, random keypair.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        PseudonymKeypair { signing_key: SigningKey::from_bytes(&seed) }
    }

    /// Reconstruct a keypair from a previously-generated 32-byte seed
    /// (e.g. loaded from the encrypted local identity store).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        PseudonymKeypair { signing_key: SigningKey::from_bytes(seed) }
    }

    /// The 32-byte seed, for persisting this keypair to encrypted
    /// local storage. Treat the returned bytes as secret.
    pub fn seed_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// The public key others verify posts against — this IS the
    /// pseudonym's on-the-wire identifier within a community.
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign a message (e.g. a post's ciphertext plus metadata).
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing_key.sign(message).to_bytes()
    }
}

/// Verify a pseudonym's signature on a message, given only their
/// public key bytes (as would be looked up from the community's
/// member list).
pub fn verify(
    public_key_bytes: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature_bytes: &[u8; SIGNATURE_LEN],
) -> Result<()> {
    let vk = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|_| KneeTieError::CryptoError("invalid pseudonym public key bytes".into()))?;
    let sig = Signature::from_bytes(signature_bytes);
    vk.verify(message, &sig)
        .map_err(|_| KneeTieError::CryptoError("pseudonym signature verification failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_succeeds() {
        let kp = PseudonymKeypair::generate();
        let msg = b"a post's content";
        let sig = kp.sign(msg);
        assert!(verify(&kp.public_key_bytes(), msg, &sig).is_ok());
    }

    #[test]
    fn wrong_message_fails_verification() {
        let kp = PseudonymKeypair::generate();
        let sig = kp.sign(b"original message");
        assert!(verify(&kp.public_key_bytes(), b"different message", &sig).is_err());
    }

    #[test]
    fn wrong_public_key_fails_verification() {
        let kp1 = PseudonymKeypair::generate();
        let kp2 = PseudonymKeypair::generate();
        let sig = kp1.sign(b"a message");
        assert!(verify(&kp2.public_key_bytes(), b"a message", &sig).is_err());
    }

    #[test]
    fn from_seed_reproduces_same_keypair() {
        let kp1 = PseudonymKeypair::generate();
        let seed = kp1.seed_bytes();
        let kp2 = PseudonymKeypair::from_seed(&seed);
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn different_generations_give_different_keys() {
        let kp1 = PseudonymKeypair::generate();
        let kp2 = PseudonymKeypair::generate();
        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn signatures_are_deterministic_for_same_key_and_message() {
        // Ed25519 signing is deterministic (RFC 8032) — signing the
        // same message twice with the same key must give the same
        // signature.
        let kp = PseudonymKeypair::generate();
        let msg = b"deterministic check";
        assert_eq!(kp.sign(msg), kp.sign(msg));
    }
}
