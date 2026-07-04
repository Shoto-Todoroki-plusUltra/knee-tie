//! Content confidentiality: epoch-based group keys.
//!
//! See key.rs for the design rationale ("Solution 3"). Summary:
//!   - Posts are encrypted under the epoch key active when posted.
//!   - Epochs rotate on revocation, not on every join.
//!   - Access to past epochs is never retroactively revoked; only
//!     future epochs are withheld from a revoked member.

pub mod key;
pub mod seal;
pub mod grant;

pub use key::{EpochKey, EpochHistory, EncryptedContent, encrypt_content, decrypt_content};
pub use seal::{SealedEpochKey, seal_epoch_key, open_sealed_epoch_key};
pub use grant::{
    HistoryAccessPolicy, MemberEpochGrant, MemberEpochKeyRing,
    grant_epochs, grant_single_epoch,
};
