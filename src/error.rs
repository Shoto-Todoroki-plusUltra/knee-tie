use thiserror::Error;

#[derive(Debug, Error)]
pub enum KneeTieError {
    #[error("WOTS verification failed")]
    WotsVerificationFailed,

    #[error("Merkle authentication path verification failed")]
    MerkleVerificationFailed,

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("DGMT signature verification failed")]
    DgmtVerificationFailed,

    #[error("Member credentials are revoked")]
    CredentialsRevoked,

    #[error("No OTS keys remaining for this member")]
    NoKeysRemaining,

    #[error("Index out of bounds: {0}")]
    IndexOutOfBounds(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
}

pub type Result<T> = std::result::Result<T, KneeTieError>;
