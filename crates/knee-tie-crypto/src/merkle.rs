//! Merkle Tree and Multi-Message Signature Scheme (MSS)
//!
//! Paper 1, Section 2.3 and Remark 1.

use crate::utils::hash::{LAMBDA, merkle_node_hash};
use crate::error::{Result, KneeTieError};

// ─── Merkle Tree ─────────────────────────────────────────────────────────────

/// A complete binary Merkle tree of height `h` with 2^h leaves.
///
/// Nodes are stored in 1-indexed BFS order:
///   nodes[1]       = root
///   nodes[2i]      = left child of nodes[i]
///   nodes[2i+1]    = right child of nodes[i]
///   nodes[2^h .. 2^(h+1)-1] = leaf nodes
///
/// `nodes` is pub(crate) so DGMT key generation can copy the IMT's
/// node array for authentication path computation. It is not part
/// of the public API.
pub struct MerkleTree {
    /// Tree height h. The tree has 2^h leaves.
    pub height: u32,
    /// All nodes in 1-indexed BFS order. nodes[0] is unused.
    pub(crate) nodes: Vec<[u8; LAMBDA]>,
}

impl MerkleTree {
    /// Build a Merkle tree from pre-hashed leaf values.
    ///
    /// `leaves` must have a power-of-two length (> 0).
    /// Leaves are accepted as-is — the caller is responsible for
    /// hashing them appropriately before calling this function.
    ///
    /// Paper §2.3: "every leaf node is the hash value of a data block,
    /// and each non-leaf node is the hash value of the concatenation
    /// of its two children"
    pub fn build(leaves: Vec<[u8; LAMBDA]>) -> Self {
        let n = leaves.len();
        assert!(n.is_power_of_two() && n > 0,
            "Merkle tree requires a power-of-two number of leaves, got {}", n);

        let height      = n.trailing_zeros();
        let total_nodes = 2 * n;

        let mut nodes = vec![[0u8; LAMBDA]; total_nodes];

        // Place leaf nodes at 1-indexed positions n..2n-1.
        for (i, leaf) in leaves.iter().enumerate() {
            nodes[n + i] = *leaf;
        }

        // Build internal nodes bottom-up.
        for i in (1..n).rev() {
            nodes[i] = merkle_node_hash(&nodes[2 * i], &nodes[2 * i + 1]);
        }

        Self { height, nodes }
    }

    /// The Merkle root — the group public key DGMT.gpk for an IMT,
    /// or the SMT root r_{i,j} / r_{i,j,k}.
    pub fn root(&self) -> &[u8; LAMBDA] {
        &self.nodes[1]
    }

    /// Leaf value at 0-based leaf index `leaf_idx`.
    pub fn leaf(&self, leaf_idx: usize) -> Option<&[u8; LAMBDA]> {
        let n = 1 << self.height;
        self.nodes.get(n + leaf_idx)
    }

    /// Number of leaves.
    pub fn num_leaves(&self) -> usize {
        1 << self.height
    }

    /// Compute the authentication path for 0-based leaf index `leaf_idx`.
    ///
    /// Returns h sibling nodes from leaf level up to (not including) root.
    ///   auth_path[0] = sibling of the leaf
    ///   auth_path[h-1] = sibling at level 1
    ///
    /// Paper §2.3: sibling nodes on the path from leaf to root.
    pub fn auth_path(&self, leaf_idx: usize) -> Result<Vec<[u8; LAMBDA]>> {
        let n = self.num_leaves();
        if leaf_idx >= n {
            return Err(KneeTieError::IndexOutOfBounds(
                format!("leaf_idx {} >= num_leaves {}", leaf_idx, n)
            ));
        }

        let mut path    = Vec::with_capacity(self.height as usize);
        let mut current = n + leaf_idx; // 1-indexed BFS position

        while current > 1 {
            // Sibling: flip the last bit of the BFS index.
            let sibling = if current % 2 == 0 { current + 1 } else { current - 1 };
            path.push(self.nodes[sibling]);
            current /= 2;
        }

        Ok(path)
    }
}

// ─── Root Computation (Verification Side) ────────────────────────────────────

/// Recompute the Merkle root from a leaf value and authentication path.
///
/// Paper §2.3, Remark 1: verifier recomputes root using leaf and auth path.
pub fn compute_root(
    leaf_value: &[u8; LAMBDA],
    leaf_idx: usize,
    auth_path: &[[u8; LAMBDA]],
    height: u32,
) -> Result<[u8; LAMBDA]> {
    if auth_path.len() != height as usize {
        return Err(KneeTieError::InvalidParameter(format!(
            "auth_path length {} does not match height {}",
            auth_path.len(), height
        )));
    }

    let mut current_value = *leaf_value;
    let mut current_idx   = leaf_idx;

    for sibling in auth_path {
        current_value = if current_idx % 2 == 0 {
            merkle_node_hash(&current_value, sibling)   // current is left child
        } else {
            merkle_node_hash(sibling, &current_value)   // current is right child
        };
        current_idx /= 2;
    }

    Ok(current_value)
}

/// Verify that a leaf belongs to a tree with a known root.
pub fn verify_leaf_membership(
    leaf_value: &[u8; LAMBDA],
    leaf_idx: usize,
    auth_path: &[[u8; LAMBDA]],
    height: u32,
    expected_root: &[u8; LAMBDA],
) -> Result<()> {
    let computed_root = compute_root(leaf_value, leaf_idx, auth_path, height)?;

    // Constant-time comparison
    let mut differs = 0u8;
    for i in 0..LAMBDA {
        differs |= computed_root[i] ^ expected_root[i];
    }

    if differs == 0 { Ok(()) } else { Err(KneeTieError::MerkleVerificationFailed) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::hash::merkle_leaf_hash; // only needed in tests

    fn build_test_tree(height: u32) -> MerkleTree {
        let n = 1usize << height;
        let leaves = (0..n)
            .map(|i| merkle_leaf_hash(format!("leaf_{}", i).as_bytes()))
            .collect();
        MerkleTree::build(leaves)
    }

    #[test]
    fn height_1_root_is_hash_of_two_leaves() {
        let leaf0 = merkle_leaf_hash(b"left");
        let leaf1 = merkle_leaf_hash(b"right");
        let tree  = MerkleTree::build(vec![leaf0, leaf1]);
        assert_eq!(tree.root(), &merkle_node_hash(&leaf0, &leaf1));
        assert_eq!(tree.height, 1);
        assert_eq!(tree.num_leaves(), 2);
    }

    #[test]
    fn tree_height_3_has_8_leaves() {
        let tree = build_test_tree(3);
        assert_eq!(tree.num_leaves(), 8);
        assert_eq!(tree.height, 3);
    }

    #[test]
    fn auth_path_length_equals_height() {
        for h in 1..=4 {
            let tree = build_test_tree(h);
            let path = tree.auth_path(0).unwrap();
            assert_eq!(path.len(), h as usize,
                "Auth path for tree of height {} must have {} elements", h, h);
        }
    }

    #[test]
    fn verify_all_leaves_in_height_3_tree() {
        let tree = build_test_tree(3);
        let root = *tree.root();
        for leaf_idx in 0..tree.num_leaves() {
            let leaf = *tree.leaf(leaf_idx).unwrap();
            let path = tree.auth_path(leaf_idx).unwrap();
            assert!(
                verify_leaf_membership(&leaf, leaf_idx, &path, tree.height, &root).is_ok(),
                "Leaf {} should verify against the tree root", leaf_idx
            );
        }
    }

    #[test]
    fn wrong_leaf_fails_verification() {
        let tree = build_test_tree(3);
        let root = *tree.root();
        let path = tree.auth_path(0).unwrap();
        assert!(
            verify_leaf_membership(&[0xFFu8; LAMBDA], 0, &path, tree.height, &root).is_err(),
            "Wrong leaf value must fail Merkle verification"
        );
    }

    #[test]
    fn wrong_path_fails_verification() {
        let tree = build_test_tree(3);
        let root = *tree.root();
        let leaf = *tree.leaf(0).unwrap();
        let wrong_path = tree.auth_path(1).unwrap(); // path for a different leaf
        assert!(
            verify_leaf_membership(&leaf, 0, &wrong_path, tree.height, &root).is_err(),
            "Auth path from different leaf must fail verification"
        );
    }

    #[test]
    fn wrong_root_fails_verification() {
        let tree = build_test_tree(3);
        let leaf = *tree.leaf(0).unwrap();
        let path = tree.auth_path(0).unwrap();
        assert!(
            verify_leaf_membership(&leaf, 0, &path, tree.height, &[0xAAu8; LAMBDA]).is_err(),
            "Verification against wrong root must fail"
        );
    }

    #[test]
    fn root_is_deterministic() {
        assert_eq!(build_test_tree(3).root(), build_test_tree(3).root(),
            "Same leaves must always produce the same root");
    }

    #[test]
    fn compute_root_matches_tree_root() {
        let tree = build_test_tree(4);
        let root = *tree.root();
        for leaf_idx in 0..tree.num_leaves() {
            let leaf     = *tree.leaf(leaf_idx).unwrap();
            let path     = tree.auth_path(leaf_idx).unwrap();
            let computed = compute_root(&leaf, leaf_idx, &path, tree.height).unwrap();
            assert_eq!(computed, root,
                "compute_root for leaf {} must match tree root", leaf_idx);
        }
    }
}
