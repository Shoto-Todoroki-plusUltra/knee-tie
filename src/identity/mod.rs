//! Pseudonymous identity: per-post signing keys, and the encrypted
//! local storage primitive used to persist them on a member's device.

pub mod pseudonym;
pub mod store;

pub use pseudonym::{
    PseudonymKeypair, verify as verify_pseudonym_signature,
    PUBLIC_KEY_LEN, SIGNATURE_LEN,
};
pub use store::{
    EncryptedBlob, seal as seal_identity, open as open_identity, SALT_LEN,
};
