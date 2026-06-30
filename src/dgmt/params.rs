//! DGMT Setup Parameters
//!
//! Paper 1, Section 4.2.1.

use crate::error::{Result, KneeTieError};

/// DGMT setup parameters: DGMT.SetPr = (hI, hSM, γ, Ttot, Nmax)
///
/// Paper §4.2.1:
///   hI  = height of IMT
///   hSM = height of each SMTMT = 2 × hS
///   γ   = number of SMTMTs per fallback node
///   Ttot = γ × (2^(hI+1) - 2) × 2^hSM
///   Nmax = maximum users, must satisfy Nmax ≤ α/2 = 2^(hS-1)
#[derive(Debug, Clone)]
pub struct DgmtParams {
    /// IMT height. IMT has 2^hI leaf nodes.
    pub h_i: u32,

    /// Each SMTMT layer height. α = 2^hS leaves per layer.
    /// Total SMTMT height hSM = 2 × hS.
    pub h_s: u32,

    /// Number of SMTMTs per fallback node.
    pub gamma: u32,

    /// Maximum users. Must satisfy Nmax ≤ α/2.
    pub n_max: u32,

    /// OTS keys per user per SMT(2). β ≥ 2 required for anonymity.
    pub beta: u32,
}

impl DgmtParams {
    /// Construct and validate DGMT parameters.
    pub fn new(h_i: u32, h_s: u32, gamma: u32, n_max: u32, beta: u32) -> Result<Self> {
        let alpha = 1u64 << h_s;

        // Paper §4.2.1 relation 4: Nmax ≤ α/2
        if n_max as u64 > alpha / 2 {
            return Err(KneeTieError::InvalidParameter(format!(
                "n_max ({}) must be ≤ α/2 = {} (where α = 2^hS = {})",
                n_max, alpha / 2, alpha
            )));
        }

        // β × Nmax must equal α
        if (beta as u64) * (n_max as u64) != alpha {
            return Err(KneeTieError::InvalidParameter(format!(
                "β × Nmax must equal α: {} × {} = {} ≠ {}",
                beta, n_max, beta as u64 * n_max as u64, alpha
            )));
        }

        // Anonymity proof requires β ≥ 2 (each user keeps one unused key)
        if beta < 2 {
            return Err(KneeTieError::InvalidParameter(
                "β must be ≥ 2 (required for anonymity proof)".into()
            ));
        }

        if h_i > 30 {
            return Err(KneeTieError::InvalidParameter(
                format!("hI={} is too large (max 30)", h_i)
            ));
        }
        if h_s > 20 {
            return Err(KneeTieError::InvalidParameter(
                format!("hS={} is too large (max 20)", h_s)
            ));
        }

        Ok(Self { h_i, h_s, gamma, n_max, beta })
    }

    /// Tiny parameters for unit tests only. Do NOT use in production.
    ///
    /// hI=2, hS=2, γ=1, Nmax=2, β=2
    /// → α=4, num_fallback_nodes=6, |FK|=6, Ttot=96
    pub fn for_testing() -> Self {
        Self { h_i: 2, h_s: 2, gamma: 1, n_max: 2, beta: 2 }
    }

    /// Total SMTMT height: hSM = 2 × hS.
    pub fn h_sm(&self) -> u32 { 2 * self.h_s }

    /// Leaves per SMT layer: α = 2^hS.
    pub fn alpha(&self) -> u32 { 1u32 << self.h_s }

    /// Total OTS key pairs: Ttot = γ × (2^(hI+1) - 2) × 2^hSM
    ///
    /// Paper §4.2.1, relation 2.
    pub fn t_tot(&self) -> u64 {
        self.gamma as u64
            * self.num_fallback_nodes() as u64
            * (1u64 << self.h_sm())
    }

    /// Total fallback keys: |FK| = γ × (2^(hI+1) - 2)
    ///
    /// Paper §4.2.1, relation 3.
    pub fn num_fallback_keys(&self) -> u64 {
        self.gamma as u64 * self.num_fallback_nodes() as u64
    }

    /// Number of IMT fallback nodes = 2^(hI+1) - 2.
    ///
    /// "All nodes of IMT, except the root node, are used as fallback nodes."
    /// (Paper §4.1)
    ///
    /// In 1-indexed BFS:
    ///   Total nodes in a height-hI tree = 2^(hI+1) - 1
    ///   Fallback nodes = total - 1 (exclude root) = 2^(hI+1) - 2
    pub fn num_fallback_nodes(&self) -> u32 {
        (1u32 << (self.h_i + 1)) - 2
    }

    /// Depth of fallback node `fallback_idx` in the IMT.
    ///
    /// Fallback nodes are 1-indexed (1..=num_fallback_nodes).
    /// BFS index = fallback_idx + 1 (root at BFS 1 is skipped).
    /// Depth = floor(log2(bfs_idx)).
    ///
    /// Used for μ in DGMT.Sig, Algorithm 7, line 2.
    pub fn fallback_node_depth(&self, fallback_idx: u32) -> u32 {
        let bfs_idx = fallback_idx + 1;
        u32::BITS - bfs_idx.leading_zeros() - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_params_are_valid() {
        let p = DgmtParams::for_testing();
        assert_eq!(p.alpha(),               4);  // 2^2
        assert_eq!(p.h_sm(),                4);  // 2×2
        assert_eq!(p.num_fallback_nodes(),  6);  // 2^3 - 2
        assert_eq!(p.num_fallback_keys(),   6);  // 1 × 6
        assert_eq!(p.t_tot(),              96);  // 1 × 6 × 2^4
    }

    #[test]
    fn nmax_too_large_is_rejected() {
        // hS=2, α=4, α/2=2. n_max=3 > 2 must fail.
        assert!(DgmtParams::new(2, 2, 1, 3, 1).is_err());
    }

    #[test]
    fn beta_times_nmax_must_equal_alpha() {
        // hS=2, α=4. β=3, n_max=2 → 6 ≠ 4, must fail.
        assert!(DgmtParams::new(2, 2, 1, 2, 3).is_err());
    }

    #[test]
    fn beta_must_be_at_least_2() {
        assert!(DgmtParams::new(2, 2, 1, 4, 1).is_err());
    }

    #[test]
    fn fallback_node_depth_is_correct() {
        let p = DgmtParams::for_testing(); // hI=2
        // 1-indexed BFS for hI=2:
        //   BFS 1: root (depth 0)   — NOT a fallback node
        //   BFS 2: depth 1          ← fallback node 1
        //   BFS 3: depth 1          ← fallback node 2
        //   BFS 4..7: depth 2       ← fallback nodes 3..6
        assert_eq!(p.fallback_node_depth(1), 1);
        assert_eq!(p.fallback_node_depth(2), 1);
        assert_eq!(p.fallback_node_depth(3), 2);
        assert_eq!(p.fallback_node_depth(6), 2);
    }

    #[test]
    fn paper_example_parameters_are_valid() {
        // Paper §4.4: hI=16, hS=16, γ=2^16, Nmax=2^12, β=2^4
        let p = DgmtParams::new(16, 16, 1 << 16, 1 << 12, 16).unwrap();
        assert_eq!(p.alpha(), 1 << 16);
        assert_eq!(p.num_fallback_nodes(), (1u32 << 17) - 2);
    }
}
