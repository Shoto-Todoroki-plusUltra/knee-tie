//! knee-tie-crypto: Post-quantum cryptographic library for Knee Tie
//!
//! Implements:
//!   Paper 1: DGMT (Fadavi et al., Cryptography 2025)
//!   Paper 2: Elligator-K1 + Kummer DH (Saha & Karati, AMC 2026)

pub mod error;
pub mod utils;
pub mod wots;
pub mod merkle;
pub mod dgmt;
pub mod elligator;

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
