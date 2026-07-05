//! knee-tie-crypto: Post-quantum cryptographic library for Knee Tie
//!
//! Implements:
//!   Paper 1: DGMT (Fadavi et al., Cryptography 2025)
//!   Paper 2: Elligator-K1 + Kummer DH (Saha & Karati, AMC 2026)
//!   Knee Tie's own design: epoch-based content confidentiality,
//!   pseudonym signing, and the local encrypted identity store.

pub mod error;
pub mod utils;
pub mod wots;
pub mod merkle;
pub mod dgmt;
pub mod elligator;
pub mod epoch;
pub mod identity;

// ── DGMT ──────────────────────────────────────────────────────────────────────
pub use error::{KneeTieError, Result};
pub use utils::hash::LAMBDA;
pub use wots::{WotsSecretKey, WotsPublicKey, WotsSignature};
pub use merkle::MerkleTree;
pub use dgmt::params::DgmtParams;
pub use dgmt::keygen::{DgmtSecretKey, DgmtPublicParams, dgmt_keygen};

// ── Elligator / Kummer DH ────────────────────────────────────────────────────
pub use elligator::{
    Fp,
    KummerPoint, KummerParams,
    elligator_k1_encode, elligator_k1_decode,
    field_to_bits, bits_to_field,
    dh_initiate, dh_complete,
    ElligatorString, DhScalar,
};

// ── Epoch keys (content confidentiality) ─────────────────────────────────────
pub use epoch::{
    EpochKey, EpochHistory, EncryptedContent, encrypt_content, decrypt_content,
    SealedEpochKey, seal_epoch_key, open_sealed_epoch_key,
    HistoryAccessPolicy, MemberEpochGrant, MemberEpochKeyRing,
    grant_epochs, grant_single_epoch,
};

// ── Identity (pseudonym signing + local encrypted storage) ──────────────────
pub use identity::{
    PseudonymKeypair, verify_pseudonym_signature, PUBLIC_KEY_LEN, SIGNATURE_LEN,
    EncryptedBlob, seal_identity, open_identity, SALT_LEN,
};
