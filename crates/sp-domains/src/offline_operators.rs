// TODO: remove once components are connected
#![allow(dead_code)]
// Chernoff lower-tail threshold for Binomial(S, p).
//
// Threshold (additive Chernoff, lower tail):
//   Let μ = S * p, where S is slots_in_epoch and p is per-slot win probability.
//   t = sqrt( 2 * μ * ln(1/τ) )
//   r = floor( μ - t ), clamped to [0, S]
//
// Property:
//   For X ~ Binomial(S, p), P[ X < r ] <= τ  (conservative bound)
//   This holds for all p in [0,1] and any S.
//
// Notes:
// - Provide ln(1/τ) as a FixedU128 constant (precomputed off-chain).
//   Examples:
//     τ = 1%   => ln(100)   ≈ 4.605170185988092  -> inner ≈ 4_605_170_185_988_092_000
//     τ = 0.5% => ln(200)   ≈ 5.298317366548036  -> inner ≈ 5_298_317_366_548_036_000
//     τ = 0.1% => ln(1000)  ≈ 6.907755278982137  -> inner ≈ 6_907_755_278_982_137_000
// - To decide throughput relevance before calling this (cheap filter), compute
//   μ_floor = floor(S * p) and require μ_floor >= E_relevance (e.g., >= 10 for τ=1%).

#[cfg(test)]
mod tests;

use crate::bundle_producer_election::calculate_threshold;
use core::cmp::max;
use sp_arithmetic::traits::{One, SaturatedConversion, Saturating, UniqueSaturatedInto, Zero};
use sp_arithmetic::{FixedPointNumber, FixedU128};
use sp_core::U256;

// For τ = 1%: ln(1/τ) = ln(100) ≈ 4.605170185988092
// Represent in FixedU128 by multiplying by 1e18 and rounding.
pub const LN_1_OVER_TAU_1_PERCENT: FixedU128 = FixedU128::from_inner(4_605_170_185_988_092_000);

// // For τ = 0.5%: ln(1/τ) = ln(200) ≈ 5.298317366548036
// // Represent in FixedU128 by multiplying by 1e18 and rounding.
// const LN_1_OVER_TAU_0_5_PERCENT: FixedU128 = FixedU128::from_inner(5_298_317_366_548_036_000);
//
// // For τ = 0.1%: ln(1/τ) = ln(1000) ≈ 6.907755278982137
// // Represent in FixedU128 by multiplying by 1e18 and rounding.
// const LN_1_OVER_TAU_0_1_PERCENT: FixedU128 = FixedU128::from_inner(6_907_755_278_982_137_000);

pub const E_BASE: u64 = 3;

// Exact per-slot win probability is p = threshold / 2^128.
// Convert that to FixedU128 (1e18 scaling) using U256 intermediates.
fn p_from_threshold(threshold: u128) -> FixedU128 {
    // inner = floor(threshold * 1e18 / 2^128)
    let num = U256::from(threshold).saturating_mul(U256::from(FixedU128::DIV));
    let den = U256::from(1u128) << 128; // 2^128
    FixedU128::from_inner((num / den).unique_saturated_into())
}

/// Chernoff lower-tail threshold r for Binomial(S, p), with false-positive at most τ.
///
/// Inputs:
/// - slots_in_epoch: S (number of slots in the epoch)
/// - p_slot: per-slot success probability p in FixedU128 (1e18 scaling)
/// - ln_one_over_tau: ln(1/τ) in FixedU128 (1e18 scaling), precomputed off-chain
///
/// Returns:
/// - r in [0, S], as u64
///
/// Formula:
///   μ = S * p
///   r = floor( μ - sqrt( 2 * μ * ln(1/τ) ) ), clamped to [0, S]
///
/// Guarantees:
///   P_honest(X < r) <= τ for X ~ Binomial(S, p). Conservative (safe) bound.
///
/// Usage:
///   let r = chernoff_threshold_fp(S, p, ln_1_over_tau);
///   if observed_bundles < r { exclude } else { keep }
fn chernoff_threshold_fp(
    slots_in_epoch: u64,
    p_slot: FixedU128,
    ln_one_over_tau: FixedU128,
) -> Option<u64> {
    if slots_in_epoch == 0 || p_slot.is_zero() {
        return Some(0);
    }

    if p_slot >= FixedU128::one() {
        return Some(slots_in_epoch);
    }

    // μ = S * p
    let mu = p_slot.saturating_mul(FixedU128::saturating_from_integer(slots_in_epoch));

    // t = sqrt( 2 * μ * ln(1/τ) )
    let t = FixedU128::from(2u128)
        .saturating_mul(mu)
        .saturating_mul(ln_one_over_tau)
        .try_sqrt()?;

    // r = floor( μ - t ), clamped to [0, S]
    Some(
        if mu > t {
            mu.saturating_sub(t).into_inner() / FixedU128::DIV
        } else {
            0
        }
        .saturated_into::<u64>()
        .clamp(0, slots_in_epoch),
    )
}

/// Check if an operator is "throughput-relevant" this epoch:
/// μ_floor = floor(S * p) >= E_relevance
///
/// Recommendation for τ = 1%:
///   E_relevance >= ceil( 2 * ln(1/τ) ) = ceil(9.21) = 10
fn is_throughput_relevant_fp(slots_in_epoch: u64, p_slot: FixedU128, e_relevance: u64) -> bool {
    let mu = p_slot.saturating_mul(FixedU128::saturating_from_integer(slots_in_epoch));
    let mu_floor: u64 = (mu.into_inner() / FixedU128::DIV).saturated_into();
    mu_floor >= e_relevance
}

// Compute E_relevance = ceil( max( E_BASE, 2 * ln(1/τ) ) ) in integer bundles.
pub fn compute_e_relevance(ln_one_over_tau: FixedU128, e_base: u64) -> u64 {
    let two_ln = FixedU128::saturating_from_integer(2)
        .saturating_mul(ln_one_over_tau)
        .into_inner()
        .div_ceil(FixedU128::DIV)
        .saturated_into();
    max(e_base, two_ln)
}

/// Expectations for one operator at epoch end (slots-based, Chernoff-calibrated).
#[derive(Debug)]
pub struct OperatorEpochExpectations {
    /// floor(μ) = floor(S * p_slot_exact): integer expected bundles this epoch.
    pub expected_bundles: u64,
    /// Chernoff lower-bound r: minimum bundles to pass with false-positive ≤ τ.
    pub min_required_bundles: u64,
}

/// Compute epoch-end expectations for an operator using the exact VRF threshold.
/// Returns None if the operator is not throughput-relevant this epoch.
///
/// Flow is:
/// - calculate_threshold(...) -> u128 threshold
/// - p_from_threshold(threshold) -> FixedU128 per-slot probability
/// - compute_e_relevance(ln_one_over_tau, e_base) -> u64 E_relevance
/// - is_throughput_relevant_fp(S, p, E_relevance) -> bool
/// - chernoff_threshold_fp(S, p, ln_one_over_tau) -> u64 r
///
/// Inputs:
/// - slots_in_epoch: S
/// - operator_stake, total_domain_stake: epoch-start stake snapshot
/// - bundle_slot_probability: (theta_num, theta_den)
/// - ln_one_over_tau: ln(1/τ) in FixedU128 (e.g., LN_1_OVER_TAU_1_PERCENT)
/// - e_base: soft relevance floor (e.g., E_BASE)
pub fn operator_expected_bundles_in_epoch(
    slots_in_epoch: u64,
    operator_stake: u128,
    total_domain_stake: u128,
    bundle_slot_probability: (u64, u64), // (theta_num, theta_den)
    ln_one_over_tau: FixedU128,
    e_base: u64,
) -> Option<OperatorEpochExpectations> {
    if slots_in_epoch == 0 {
        return None;
    }

    // Exact per-slot probability from runtime VRF threshold
    let threshold =
        calculate_threshold(operator_stake, total_domain_stake, bundle_slot_probability)?;
    let p_slot = p_from_threshold(threshold);
    if p_slot.is_zero() {
        return None;
    }

    // Throughput relevance: μ_floor >= E_relevance
    let e_rel = compute_e_relevance(ln_one_over_tau, e_base);
    if !is_throughput_relevant_fp(slots_in_epoch, p_slot, e_rel) {
        return None;
    }

    // Expected bundles (floor μ) and Chernoff lower-bound r
    let mu_fp = p_slot.saturating_mul(FixedU128::saturating_from_integer(slots_in_epoch));
    let expected_bundles: u64 = (mu_fp.into_inner() / FixedU128::DIV).saturated_into();
    let min_required_bundles = chernoff_threshold_fp(slots_in_epoch, p_slot, ln_one_over_tau)?;

    Some(OperatorEpochExpectations {
        expected_bundles,
        min_required_bundles,
    })
}
