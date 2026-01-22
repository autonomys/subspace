use crate::bundle_producer_election::calculate_threshold;
use crate::offline_operators::{
    E_BASE, LN_1_OVER_TAU_0_5_PERCENT, LN_1_OVER_TAU_1_PERCENT, chernoff_threshold_fp,
    compute_e_relevance, is_throughput_relevant_fp, operator_expected_bundles_in_epoch,
    p_from_threshold,
};
use num_traits::{One, Zero};
use prop_test::proptest::prelude::{ProptestConfig, Strategy};
use prop_test::proptest::strategy::ValueTree;
use prop_test::proptest::test_runner::TestRunner;
use prop_test::proptest::{prop_assert, prop_assert_eq, prop_assume, proptest};
use sp_arithmetic::traits::{SaturatedConversion, Saturating};
use sp_arithmetic::{FixedPointNumber, FixedU128};

// For τ = 0.1%: ln(1/τ) = ln(1000) ≈ 6.907755278982137
// Represent in FixedU128 by multiplying by 1e18 and rounding.
const LN_1_OVER_TAU_0_1_PERCENT: FixedU128 = FixedU128::from_inner(6_907_755_278_982_137_000);

#[test]
fn test_ln_1_over_tau_1_value() {
    // Dynamically compute ln(100) in floating point
    // Convert to FixedU128 representation (scaled by 1e18)
    let computed_ln_1_over_tau_1 = FixedU128::from_inner((f64::ln(100.0) * 1e18).round() as u128);

    // Check equality of integer fixed-point representation
    assert_eq!(LN_1_OVER_TAU_1_PERCENT, computed_ln_1_over_tau_1,);
}

#[test]
fn test_ln_1_over_tau_0_5_value() {
    // Dynamically compute ln(200) in floating point
    // Convert to FixedU128 representation (scaled by 1e18)
    let computed_ln_1_over_tau_0_5 = FixedU128::from_inner((f64::ln(200.0) * 1e18).round() as u128);

    // Check equality of integer fixed-point representation
    assert_eq!(LN_1_OVER_TAU_0_5_PERCENT, computed_ln_1_over_tau_0_5,);
}

#[test]
fn test_chernoff_basic() {
    // S = 600, p = 0.05 (μ = 30). τ = 0.5% -> ln(200)
    let s = 600u64;
    let p = FixedU128::saturating_from_rational(5u128, 100u128);
    let r = chernoff_threshold_fp(s, p, LN_1_OVER_TAU_0_5_PERCENT).unwrap();
    // Chernoff is conservative; r will be noticeably below μ.
    // Expect r around low/mid-teens.
    assert!(r > 0 && r < 30, "r should be between 1 and 29, got {r}");
}

#[test]
fn test_relevance_filter() {
    // S = 600, p = ~1.67% -> μ ≈ 10
    let s = 600u64;
    let p = FixedU128::saturating_from_rational(167u128, 10_000u128); // ~0.0167
    assert!(is_throughput_relevant_fp(s, p, 10));
    let p_small = FixedU128::saturating_from_rational(1u128, 10_000u128); // 0.01%
    assert!(!is_throughput_relevant_fp(s, p_small, 10));
}

#[test]
fn test_p_from_threshold() {
    // If threshold = 2^128 - 1, p ≈ 1 (minus 2^-128)
    let max = u128::MAX; // 2^128 - 1
    let p = p_from_threshold(max);
    assert!(p <= FixedU128::from(1u128));
    // And definitely > 0.999...
    let nine_nines = FixedU128::saturating_from_rational(
        999_999_999_999_999_999u128,
        1_000_000_000_000_000_000u128,
    );
    assert!(p < FixedU128::one());
    assert!(p >= nine_nines);
}

fn e_rel_1pct() -> u64 {
    compute_e_relevance(LN_1_OVER_TAU_0_5_PERCENT, E_BASE)
}

#[test]
fn e_relevance_is_11_for_tau_0_5_pct() {
    // 2 * ln(200) ≈ 10.5966347331 -> ceil = 11; max(E_BASE=3, 11) = 11
    assert_eq!(e_rel_1pct(), 11);
}

#[test]
fn returns_none_when_no_slots_or_zero_threshold_inputs() {
    // S = 0
    assert!(
        operator_expected_bundles_in_epoch(
            0,
            1_000,     // operator_stake
            1_000_000, // total_domain_stake
            (1, 1),    // theta
            LN_1_OVER_TAU_0_5_PERCENT,
            E_BASE,
        )
        .is_none()
    );

    // total_domain_stake = 0 -> calculate_threshold returns None
    assert!(
        operator_expected_bundles_in_epoch(
            600,
            1_000, // operator_stake
            0,     // total_domain_stake
            (1, 1),
            LN_1_OVER_TAU_0_5_PERCENT,
            E_BASE,
        )
        .is_none()
    );

    // operator_stake = 0 -> threshold = 0 -> p_slot = 0 -> None
    assert!(
        operator_expected_bundles_in_epoch(
            600,
            0,                         // operator_stake
            1_000_000_000_000_000_000, // total_domain_stake
            (1, 1),
            LN_1_OVER_TAU_0_5_PERCENT,
            E_BASE,
        )
        .is_none()
    );
}

#[test]
fn small_mu_is_not_throughput_relevant() {
    // S = 600, share ~ 0.5% => μ ≈ 3 < E_relevance(=10) -> None
    let total = 1_000_000_000_000_000_000u128;
    let operator = total / 200; // 0.5%
    assert!(
        operator_expected_bundles_in_epoch(
            600,
            operator,
            total,
            (1, 1),
            LN_1_OVER_TAU_0_5_PERCENT,
            E_BASE,
        )
        .is_none()
    );
}

#[test]
fn relevant_operator_produces_some_expectations() {
    // S = 600, share ~ 2% => μ ≈ 12 >= 11 -> Some(...)
    let total = 1_000_000_000_000_000_000u128;
    let operator = total / 30; // 3.33%
    let exp = operator_expected_bundles_in_epoch(
        600,
        operator,
        total,
        (1, 1),
        LN_1_OVER_TAU_0_5_PERCENT,
        E_BASE,
    )
    .expect("should be relevant");
    // expected_bundles should be >= E_relevance (11) for τ=0.5%
    assert!(exp.expected_bundles >= e_rel_1pct());
    // Chernoff threshold is a lower bound; must be <= expected_bundles
    assert!(exp.min_required_bundles <= exp.expected_bundles);
    // And strictly positive in this regime
    assert!(exp.min_required_bundles > 0);
}

#[test]
fn near_full_stake_behaves_sensibly() {
    // S = 100, operator == total -> p ≈ 1 - 2^-128
    let total = 1_000_000_000_000_000_000u128;
    let operator = total; // 100% stake
    let exp = operator_expected_bundles_in_epoch(
        100,
        operator,
        total,
        (1, 1),
        LN_1_OVER_TAU_0_5_PERCENT,
        E_BASE,
    )
    .expect("should be relevant");
    // Expected bundles floor should be S - 1 (since p ~= 1 - epsilon)
    assert!(exp.expected_bundles >= 99 && exp.expected_bundles <= 100);
    // Lower bound should be <= expected, and > 0
    assert!(exp.min_required_bundles <= exp.expected_bundles);
    assert!(exp.min_required_bundles > 0);
}

#[test]
fn monotonic_in_stake_when_relevant() {
    // Fix S and total; increasing operator_stake should not decrease expectations
    let s = 600u64;
    let total = 1_000_000_000_000_000_000u128;

    let tests = [
        (total / 200, false), // 0.5% -> not relevant (μ≈3)
        (total / 100, false), // 1%   -> not relevant (μ≈6)
        (total / 59, false),  // ~1.695% -> μ_floor >= 10 -> not relevant
        (total / 50, true),   // 2%   -> μ≈12 relevant
        (total / 20, true),   // 5%   -> μ≈30 relevant
    ];

    let mut last_exp_bundles = 0u64;

    for (stake, relevant) in tests {
        let out = operator_expected_bundles_in_epoch(
            s,
            stake,
            total,
            (1, 1),
            LN_1_OVER_TAU_0_5_PERCENT,
            E_BASE,
        );

        // check relevance
        assert_eq!(out.is_some(), relevant);

        if let Some(exp) = out {
            if relevant {
                // Once relevant, expected_bundles should be non-decreasing with stake
                assert!(exp.expected_bundles >= last_exp_bundles);
                last_exp_bundles = exp.expected_bundles;
            }

            // Lower bound is never greater than expected
            assert!(exp.min_required_bundles <= exp.expected_bundles);
        }
    }
}

#[test]
fn p_from_threshold_zero_is_zero() {
    let p = p_from_threshold(0);
    assert!(p.is_zero());
}

#[test]
fn compute_e_relevance_variants() {
    // τ = 1% -> 2*ln(100) ≈ 9.21 -> ceil = 10; max(E_BASE=3, 10) = 10
    assert_eq!(compute_e_relevance(LN_1_OVER_TAU_1_PERCENT, E_BASE), 10);
    // τ = 0.5% -> 2*ln(200) ≈ 10.596 -> ceil = 11
    assert_eq!(compute_e_relevance(LN_1_OVER_TAU_0_5_PERCENT, E_BASE), 11);
    // τ = 0.1% -> 2*ln(1000) ≈ 13.815 -> ceil = 14
    assert_eq!(compute_e_relevance(LN_1_OVER_TAU_0_1_PERCENT, E_BASE), 14);
}

#[test]
fn chernoff_monotone_in_tau() {
    // For fixed S, p: as τ decreases (ln(1/τ) increases), threshold r decreases or stays.
    let s = 600u64;
    let p = FixedU128::saturating_from_rational(5u128, 100u128); // 5%
    let r_1pct = chernoff_threshold_fp(s, p, LN_1_OVER_TAU_1_PERCENT);
    let r_05pct = chernoff_threshold_fp(s, p, LN_1_OVER_TAU_0_5_PERCENT);
    let r_01pct = chernoff_threshold_fp(s, p, LN_1_OVER_TAU_0_1_PERCENT);
    assert!(r_05pct <= r_1pct, "r should decrease as τ decreases");
    assert!(
        r_01pct <= r_05pct,
        "r should decrease further for smaller τ"
    );
}

#[test]
fn chernoff_edges_p_zero_or_one() {
    let s = 123u64;
    let r_zero =
        chernoff_threshold_fp(s, FixedU128::from_inner(0), LN_1_OVER_TAU_0_5_PERCENT).unwrap();
    assert_eq!(r_zero, 0);
    let r_one = chernoff_threshold_fp(s, FixedU128::one(), LN_1_OVER_TAU_0_5_PERCENT).unwrap();
    assert_eq!(r_one, s);
}

#[test]
fn throughput_relevance_boundary() {
    // Construct p so that floor(S * p) == E_relevance, should be relevant.
    let e_rel = compute_e_relevance(LN_1_OVER_TAU_0_5_PERCENT, E_BASE); // 11
    let s = 600u64;
    let p = FixedU128::saturating_from_rational(e_rel as u128, s as u128);
    // at boundary is not relevant
    assert!(!is_throughput_relevant_fp(s, p, e_rel));
    // Just below boundary
    let p_below = FixedU128::saturating_from_rational((e_rel - 1) as u128, s as u128);
    assert!(!is_throughput_relevant_fp(s, p_below, e_rel));
    // Just above boundary
    let p_below = FixedU128::saturating_from_rational((e_rel + 1) as u128, s as u128);
    assert!(is_throughput_relevant_fp(s, p_below, e_rel));
}

#[test]
fn operator_expected_bundles_theta_one() {
    // S=600, ~2% share -> μ≈12 -> relevant, expect some thresholds
    let s = 600u64;
    let total = 1_000_000_000_000_000_000u128;
    let operator = total / 50; // 2%
    let out = operator_expected_bundles_in_epoch(
        s,
        operator,
        total,
        (1, 1),
        LN_1_OVER_TAU_0_5_PERCENT,
        E_BASE,
    )
    .expect("relevant operator should produce expectations");
    // Expected bundles >= relevance floor
    assert!(out.expected_bundles >= compute_e_relevance(LN_1_OVER_TAU_0_5_PERCENT, E_BASE));
    // r <= expected
    assert!(out.min_required_bundles <= out.expected_bundles);
    // monotone sanity: increasing S increases expected bundles
    let out2 = operator_expected_bundles_in_epoch(
        s + 100,
        operator,
        total,
        (1, 1),
        LN_1_OVER_TAU_0_5_PERCENT,
        E_BASE,
    )
    .expect("still relevant at larger S");
    assert!(out2.expected_bundles >= out.expected_bundles);
}

#[test]
fn operator_expected_bundles_theta_half_not_relevant() {
    // With theta = 1/2, expected bundles halves; under relevance floor => None.
    let s = 600u64;
    let total = 1_000_000_000_000_000_000u128;
    let operator = total / 50; // 2% stake; μ would be ~12 at theta=1
    // theta = 1/2 -> μ ≈ 6 -> below 11 => None
    let out = operator_expected_bundles_in_epoch(
        s,
        operator,
        total,
        (1, 2),
        LN_1_OVER_TAU_0_5_PERCENT,
        E_BASE,
    );
    assert!(out.is_none());
}

#[test]
fn operator_expected_bundles_handles_huge_total_and_small_op() {
    // Very large totals but still relevant stake; ensure no overflow and sensible output.
    let s = 1_000u64;
    let total = u128::MAX / 10; // huge
    let operator = total / 50; // 2%
    let out = operator_expected_bundles_in_epoch(
        s,
        operator,
        total,
        (1, 1),
        LN_1_OVER_TAU_0_5_PERCENT,
        E_BASE,
    )
    .expect("should be relevant");
    assert!(out.expected_bundles >= compute_e_relevance(LN_1_OVER_TAU_0_5_PERCENT, E_BASE));
    assert!(out.min_required_bundles <= out.expected_bundles);
}

// Helper: compute floor(μ) directly from threshold for cross-checks.
fn mu_floor_from_threshold(
    slots_in_epoch: u64,
    operator_stake: u128,
    total_domain_stake: u128,
    theta: (u64, u64),
) -> u64 {
    if slots_in_epoch == 0 || total_domain_stake == 0 || theta.1 == 0 {
        return 0;
    }
    let Some(th) = calculate_threshold(operator_stake, total_domain_stake, theta) else {
        return 0;
    };
    let p = p_from_threshold(th);
    let mu_fp = p.saturating_mul(FixedU128::from(slots_in_epoch as u128));
    let mu_floor: u64 = (mu_fp.into_inner() / FixedU128::DIV).saturated_into();
    mu_floor
}

// Strategy helpers
fn slots_strategy() -> impl Strategy<Value = u64> {
    // Keep S modest so tests run fast but still meaningful
    1u64..=2_000u64
}

fn total_stake_strategy() -> impl Strategy<Value = u128> {
    // Avoid extremes to keep math fast, but cover wide range
    // [1, 1e24]
    1u128..=1_000_000_000_000_000_000_000_000u128
}

fn operator_stake_strategy(total: u128) -> impl Strategy<Value = u128> {
    // Sample a percentage in [0, 1], then scale by total
    // Using 0..=1_000_000 (ppm) gives fine granularity.
    (0u128..=1_000_000u128).prop_map(move |ppm| total.saturating_mul(ppm) / 1_000_000u128)
}

fn theta_strategy() -> impl Strategy<Value = (u64, u64)> {
    // Denominator in [1, 10], numerator in [1, den] so theta ∈ (0, 1]
    (1u64..=10u64).prop_flat_map(|den| (1u64..=den).prop_map(move |num| (num, den)))
}

fn prop_test_config() -> ProptestConfig {
    let config = ProptestConfig::default();
    ProptestConfig {
        cases: 10000,
        max_global_rejects: 100000,
        max_shrink_iters: 100000,
        ..config
    }
}

proptest! {
    // 1) Relevance and threshold consistency:
    //    - If Some(expectations), then expected_bundles >= E_relevance and r <= expected.
    //    - If None, then either μ_floor < E_relevance or p == 0 (captured by μ_floor == 0) or S == 0.
    #![proptest_config(prop_test_config())]
    #[test]
    fn prop_relevance_and_threshold_consistency(
        s in slots_strategy(),
        total in total_stake_strategy(),
        theta in theta_strategy(),
    ) {
        // Operator stake depends on total -> sample after total is known
        prop_assume!(total > 0 && theta.1 > 0);
        let stake = operator_stake_strategy(total).new_tree(&mut TestRunner::default()).unwrap().current();

        let out = operator_expected_bundles_in_epoch(
            s, stake, total, theta, LN_1_OVER_TAU_0_5_PERCENT, E_BASE
        );

        let mu_floor = mu_floor_from_threshold(s, stake, total, theta);
        let e_rel = e_rel_1pct();

        match out {
            Some(exp) => {
                // Expected matches μ_floor from the same inputs
                prop_assert_eq!(exp.expected_bundles, mu_floor);
                // Relevance
                prop_assert!(exp.expected_bundles >= e_rel);
                // Lower bound never exceeds expected and never exceeds S
                prop_assert!(exp.min_required_bundles <= exp.expected_bundles);
                prop_assert!(exp.min_required_bundles <= s);
                prop_assert!(exp.expected_bundles <= s);
            }
            None => {
                // Not relevant: μ_floor below relevance floor, or zero probability -> μ_floor = 0
                prop_assert!(mu_floor < e_rel);
            }
        }
    }

    // 2) Monotonicity in stake (when relevant):
    //    If lower stake is relevant, then higher stake (>=) must also be relevant and
    //    expected_bundles (floor μ) must be non-decreasing.
    #[test]
    fn prop_monotonic_in_stake_when_relevant(
        s in slots_strategy(),
        total in total_stake_strategy(),
        theta in theta_strategy(),
        lo_pct in 0u128..=900_000u128,   // up to 90%
        hi_delta in 0u128..=100_000u128, // add up to +10%
    ) {
        prop_assume!(total > 0 && theta.1 > 0);
        let lo_ppm = lo_pct;
        let hi_ppm = (lo_pct + hi_delta).min(1_000_000u128);

        let stake_lo = total.saturating_mul(lo_ppm) / 1_000_000u128;
        let stake_hi = total.saturating_mul(hi_ppm) / 1_000_000u128;

        // Ensure monotone inputs
        prop_assume!(stake_hi >= stake_lo);

        let out_lo = operator_expected_bundles_in_epoch(
            s, stake_lo, total, theta, LN_1_OVER_TAU_0_5_PERCENT, E_BASE
        );
        let out_hi = operator_expected_bundles_in_epoch(
            s, stake_hi, total, theta, LN_1_OVER_TAU_0_5_PERCENT, E_BASE
        );

        if let Some(exp_lo) = out_lo {
            // Higher stake should also be relevant
            let exp_hi = out_hi.expect("higher stake must remain relevant");
            // Non-decreasing expected bundles
            prop_assert!(exp_hi.expected_bundles >= exp_lo.expected_bundles);
            // r <= expected (sanity)
            prop_assert!(exp_lo.min_required_bundles <= exp_lo.expected_bundles);
            prop_assert!(exp_hi.min_required_bundles <= exp_hi.expected_bundles);
            prop_assert!(exp_hi.expected_bundles <= s);
            prop_assert!(exp_lo.expected_bundles <= s);
        }
    }

    // 3) Monotonicity in slots (when relevant):
    //    If an operator is relevant at S1, then increasing the slots to S2 >= S1
    //    should keep it relevant and not decrease expected bundles.
    #[test]
    fn prop_monotonic_in_slots_when_relevant(
        s1 in 1u64..=1500u64,
        s2 in 1u64..=1500u64,
        total in total_stake_strategy(),
        theta in theta_strategy(),
        ppm in 0u128..=1_000_000u128,
    ) {
        prop_assume!(total > 0 && theta.1 > 0);
        let stake = total.saturating_mul(ppm) / 1_000_000u128;
        let (s_min, s_max) = if s1 <= s2 { (s1, s2) } else { (s2, s1) };

        let out_min = operator_expected_bundles_in_epoch(
            s_min, stake, total, theta, LN_1_OVER_TAU_0_5_PERCENT, E_BASE
        );
        let out_max = operator_expected_bundles_in_epoch(
            s_max, stake, total, theta, LN_1_OVER_TAU_0_5_PERCENT, E_BASE
        );

        if let Some(exp_min) = out_min {
            // At more slots, still relevant
            let exp_max = out_max.expect("more slots should not drop relevance");
            // Expected bundles should not decrease
            prop_assert!(exp_max.expected_bundles >= exp_min.expected_bundles);
            // r <= expected (sanity)
            prop_assert!(exp_min.min_required_bundles <= exp_min.expected_bundles);
            prop_assert!(exp_max.min_required_bundles <= exp_max.expected_bundles);
        }
    }

    // 4) Monotonicity in theta (when relevant):
    //    With the same denominator, increasing numerator should not decrease expectations.
    #[test]
    fn prop_monotonic_in_theta_num_when_relevant(
        s in slots_strategy(),
        total in total_stake_strategy(),
        ppm in 0u128..=1_000_000u128,
        den in 1u64..=10u64,
        num_lo in 1u64..=9u64, // keep room for num_hi
        delta in 0u64..=9u64,
    ) {
        prop_assume!(total > 0);
        let stake = total.saturating_mul(ppm) / 1_000_000u128;

        let num_hi = (num_lo + delta).min(den); // ensure theta_hi >= theta_lo
        prop_assume!(num_hi >= num_lo);

        let theta_lo = (num_lo, den);
        let theta_hi = (num_hi, den);

        let out_lo = operator_expected_bundles_in_epoch(
            s, stake, total, theta_lo, LN_1_OVER_TAU_0_5_PERCENT, E_BASE
        );
        let out_hi = operator_expected_bundles_in_epoch(
            s, stake, total, theta_hi, LN_1_OVER_TAU_0_5_PERCENT, E_BASE
        );

        if let Some(exp_lo) = out_lo {
            // With higher theta, still relevant
            let exp_hi = out_hi.expect("higher theta should not drop relevance");
            // Expected bundles should not decrease
            prop_assert!(exp_hi.expected_bundles >= exp_lo.expected_bundles);
            // r <= expected (sanity)
            prop_assert!(exp_lo.min_required_bundles <= exp_lo.expected_bundles);
            prop_assert!(exp_hi.min_required_bundles <= exp_hi.expected_bundles);
            prop_assert!(exp_hi.expected_bundles <= s);
            prop_assert!(exp_lo.expected_bundles <= s);
        }
    }
}
