//! Granting members access to epochs, and a member-side key ring for
//! epoch keys they have been granted.

use std::collections::BTreeMap;
use crate::elligator::{KummerParams, KummerPoint, ElligatorString, DhScalar};
use crate::epoch::key::{EpochKey, EpochHistory};
use crate::epoch::seal::{SealedEpochKey, seal_epoch_key, open_sealed_epoch_key};
use crate::error::Result;

/// Founder-configurable policy: how much history a newly joined member
/// can read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryAccessPolicy {
    /// New members receive sealed keys for every epoch since the
    /// community's founding.
    FullHistory,
    /// New members only receive the current epoch's key; earlier posts
    /// remain unreadable to them.
    FromJoinDate,
}

/// A bundle of sealed epoch keys addressed to one member's static
/// public value — what actually gets transmitted / stored server-side.
pub struct MemberEpochGrant {
    pub member_static_pub: ElligatorString,
    pub sealed_keys: Vec<SealedEpochKey>,
}

/// Manager-side: grant a member access to epochs per the given policy.
///
/// Called once at join time (with the community's configured policy),
/// and again with a single-epoch grant whenever the epoch rotates and
/// this member is still active (see `grant_single_epoch` below).
pub fn grant_epochs(
    history: &EpochHistory,
    member_static_pub: &ElligatorString,
    policy: HistoryAccessPolicy,
    params: &KummerParams,
    base: &KummerPoint,
) -> Result<MemberEpochGrant> {
    let epochs: &[EpochKey] = match policy {
        HistoryAccessPolicy::FullHistory  => history.epochs_from(0),
        HistoryAccessPolicy::FromJoinDate => {
            std::slice::from_ref(history.current_epoch())
        }
    };

    let mut sealed_keys = Vec::with_capacity(epochs.len());
    for ek in epochs {
        sealed_keys.push(seal_epoch_key(ek, member_static_pub, params, base)?);
    }

    Ok(MemberEpochGrant { member_static_pub: *member_static_pub, sealed_keys })
}

/// Grant a single, specific epoch to a member (used when an epoch
/// rotates and this member remains active — they do not need the
/// earlier epochs re-sealed, only the new one).
pub fn grant_single_epoch(
    epoch_key: &EpochKey,
    member_static_pub: &ElligatorString,
    params: &KummerParams,
    base: &KummerPoint,
) -> Result<SealedEpochKey> {
    seal_epoch_key(epoch_key, member_static_pub, params, base)
}

/// Member-side: the set of epoch keys this member has unsealed so far,
/// keyed by epoch number for fast lookup when decrypting a post.
pub struct MemberEpochKeyRing {
    keys: BTreeMap<u64, [u8; 32]>,
}

impl MemberEpochKeyRing {
    pub fn new() -> Self {
        MemberEpochKeyRing { keys: BTreeMap::new() }
    }

    /// Unseal a received bundle using this member's own static scalar,
    /// adding every successfully-opened key to the ring.
    pub fn absorb_grant(
        &mut self,
        grant: &MemberEpochGrant,
        my_scalar: &DhScalar,
        params: &KummerParams,
    ) -> Result<()> {
        for sealed in &grant.sealed_keys {
            let ek = open_sealed_epoch_key(sealed, my_scalar, params)?;
            self.keys.insert(ek.epoch_number, ek.key);
        }
        Ok(())
    }

    /// Unseal and add a single epoch key (e.g. after an epoch rotation).
    pub fn absorb_single(
        &mut self,
        sealed: &SealedEpochKey,
        my_scalar: &DhScalar,
        params: &KummerParams,
    ) -> Result<()> {
        let ek = open_sealed_epoch_key(sealed, my_scalar, params)?;
        self.keys.insert(ek.epoch_number, ek.key);
        Ok(())
    }

    /// Look up the key for a specific epoch, if this member has it.
    pub fn get(&self, epoch_number: u64) -> Option<EpochKey> {
        self.keys.get(&epoch_number)
            .map(|k| EpochKey { epoch_number, key: *k })
    }

    /// How many distinct epochs this member currently has keys for.
    pub fn len(&self) -> usize { self.keys.len() }
    pub fn is_empty(&self) -> bool { self.keys.is_empty() }
}

impl Default for MemberEpochKeyRing {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elligator::field::{base_point_x, base_point_z};
    use crate::elligator::dh_initiate;

    fn params() -> KummerParams { KummerParams::p25519() }
    fn base() -> KummerPoint { KummerPoint::new(base_point_x(), base_point_z()) }

    #[test]
    fn full_history_policy_grants_all_epochs() {
        let p = params();
        let b = base();
        let mut history = EpochHistory::new();
        history.rotate();
        history.rotate(); // now at epoch 2, 3 epochs total (0,1,2)

        let (member_pub, member_sk) = dh_initiate(&p, &b).unwrap();
        let grant = grant_epochs(&history, &member_pub, HistoryAccessPolicy::FullHistory, &p, &b).unwrap();

        assert_eq!(grant.sealed_keys.len(), 3, "FullHistory must grant all 3 epochs");

        let mut ring = MemberEpochKeyRing::new();
        ring.absorb_grant(&grant, &member_sk, &p).unwrap();
        assert_eq!(ring.len(), 3);
        assert!(ring.get(0).is_some());
        assert!(ring.get(1).is_some());
        assert!(ring.get(2).is_some());
    }

    #[test]
    fn from_join_date_policy_grants_only_current_epoch() {
        let p = params();
        let b = base();
        let mut history = EpochHistory::new();
        history.rotate();
        history.rotate(); // current epoch = 2

        let (member_pub, member_sk) = dh_initiate(&p, &b).unwrap();
        let grant = grant_epochs(&history, &member_pub, HistoryAccessPolicy::FromJoinDate, &p, &b).unwrap();

        assert_eq!(grant.sealed_keys.len(), 1, "FromJoinDate must grant exactly 1 epoch");

        let mut ring = MemberEpochKeyRing::new();
        ring.absorb_grant(&grant, &member_sk, &p).unwrap();
        assert_eq!(ring.len(), 1);
        assert!(ring.get(0).is_none(), "must NOT have access to epoch 0");
        assert!(ring.get(1).is_none(), "must NOT have access to epoch 1");
        assert!(ring.get(2).is_some(), "must have access to current epoch 2");
    }

    #[test]
    fn revoked_member_does_not_get_new_epoch() {
        // Simulates: member A joins (FullHistory), then member B is
        // revoked, triggering a rotation. A single-epoch grant is sent
        // to every remaining active member (which we simulate for A),
        // but NOT to the revoked member B — so B's key ring never
        // receives the new epoch, and cannot decrypt future content.
        let p = params();
        let b = base();
        let mut history = EpochHistory::new();

        let (a_pub, a_sk) = dh_initiate(&p, &b).unwrap();
        let (b_pub, b_sk) = dh_initiate(&p, &b).unwrap();

        // Both A and B initially get epoch 0.
        let grant_a0 = grant_epochs(&history, &a_pub, HistoryAccessPolicy::FullHistory, &p, &b).unwrap();
        let mut ring_a = MemberEpochKeyRing::new();
        ring_a.absorb_grant(&grant_a0, &a_sk, &p).unwrap();

        let mut ring_b = MemberEpochKeyRing::new();
        // (B would have received the same epoch 0 grant at their own
        //  join time; we just directly seal+absorb it here for test
        //  simplicity.)
        let sealed_b0 = grant_single_epoch(history.get(0).unwrap(), &b_pub, &p, &b).unwrap();
        ring_b.absorb_single(&sealed_b0, &b_sk, &p).unwrap();

        // B is revoked; epoch rotates.
        let new_epoch = history.rotate();

        // New epoch is sealed and granted ONLY to A (the still-active member).
        let sealed_new_for_a = grant_single_epoch(new_epoch, &a_pub, &p, &b).unwrap();
        ring_a.absorb_single(&sealed_new_for_a, &a_sk, &p).unwrap();

        // A can now read epoch 1; B never received a sealed bundle for
        // it and so has no way to add it to their ring.
        assert!(ring_a.get(1).is_some(), "active member A must have the new epoch");
        assert!(ring_b.get(1).is_none(), "revoked member B must NOT have the new epoch");

        // B retains their previously-granted epoch 0 access (documented tradeoff).
        assert!(ring_b.get(0).is_some(),
            "revoked member B retains access to epochs granted before revocation");
    }
}
