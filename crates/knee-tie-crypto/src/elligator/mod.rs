//! Elligator-K1 and Kummer line DH (Paper 2: Saha & Karati, AMC 2026).
//!
//! Modules:
//!   field       — F_{p25519} arithmetic
//!   kummer      — Squared Kummer line Ka²,b² arithmetic
//!   elligator_k1 — Elligator-K1 encoding/decoding
//!   dh          — Diffie-Hellman key exchange using Kummer line + Elligator

pub mod field;
pub mod kummer;
pub mod elligator_k1;
pub mod dh;

// Re-export the types most callers need
pub use field::Fp;
pub use kummer::{KummerPoint, KummerParams, scalar_mult, clamp_scalar};
pub use elligator_k1::{elligator_k1_encode, elligator_k1_decode, field_to_bits, bits_to_field};
pub use dh::{DhKeyPair, ElligatorString, DhScalar, dh_initiate, dh_complete};
