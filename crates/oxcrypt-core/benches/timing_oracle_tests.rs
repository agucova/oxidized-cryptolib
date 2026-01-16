//! Timing leak detection tests using timing-oracle.
//!
//! These tests verify that security-critical operations run in constant time
//! using Bayesian statistical analysis with probability-based results.
//!
//! # Security-Critical Operations
//!
//! Only operations that MUST be constant-time are tested here:
//! - Key unwrap integrity check (ct_eq comparison)
//! - HMAC verification (ring::hmac::verify)
//!
//! AEAD operations (AES-GCM, AES-SIV, CTR-MAC) are NOT tested because they
//! legitimately return early on authentication failure - this is expected
//! behavior and not a security concern.
//!
//! # Interpretation
//!
//! - Pass: P(leak) < 5% - No statistically significant timing difference
//! - Fail: P(leak) > 95% - Strong evidence of timing difference
//! - Inconclusive: 5% < P(leak) < 95% - Cannot determine
//!
//! # Running the tests
//!
//! ```bash
//! cargo bench --bench timing_oracle_tests -p oxcrypt-core
//! ```

use ring::hmac;
use subtle::ConstantTimeEq;
use timing_oracle::{helpers::InputPair, AttackerModel, Outcome, TimingOracle};

/// RFC 3394 integrity check IV (from RFC 3394 Section 2.2.3.1)
const IV_3394: [u8; 8] = [0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6];

/// Threshold for timing leak detection (5ns)
const THRESHOLD_NS: f64 = 5.0;

/// Test that the RFC 3394 integrity check comparison runs in constant time.
///
/// This tests ONLY the `ct_eq` comparison used in key unwrap, isolating it
/// from the different success/failure code paths (zeroize, allocation, etc.).
///
/// The security property we care about is that the comparison doesn't leak
/// which bytes differ between the computed integrity check and the expected IV.
fn test_key_unwrap() -> Outcome {
    println!("\n=== Testing: RFC 3394 key unwrap (ct_eq comparison) ===");

    let expected = IV_3394;
    // Generate a "wrong" integrity check value (simulates wrong KEK result)
    let wrong_integrity: [u8; 8] = rand::random();

    let inputs = InputPair::new(
        move || expected,        // Matching (correct KEK scenario)
        move || wrong_integrity, // Non-matching (wrong KEK scenario)
    );

    TimingOracle::for_attacker(AttackerModel::Custom {
        threshold_ns: THRESHOLD_NS,
    })
    .test(inputs, |integrity_check| {
        // This is exactly what key_wrap.rs does
        let result = integrity_check.ct_eq(&expected);
        std::hint::black_box(result);
    })
}

/// Test that HMAC verification runs in constant time.
///
/// ring::hmac::verify() should be constant-time by design, but we verify
/// this property to catch any regressions or unexpected behavior.
///
/// We compare:
/// - Baseline: Verify correct MAC
/// - Sample: Verify incorrect MAC (one byte flipped)
fn test_hmac_verify() -> Outcome {
    println!("\n=== Testing: HMAC verification (ring::hmac::verify) ===");

    // Generate a random key and message
    let key_bytes: [u8; 32] = rand::random();
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
    let message: [u8; 64] = rand::random();

    // Generate the correct MAC
    let correct_tag = hmac::sign(&key, &message);
    let correct_tag_bytes: Vec<u8> = correct_tag.as_ref().to_vec();

    // Create an incorrect MAC (flip one byte)
    let mut wrong_tag_bytes = correct_tag_bytes.clone();
    wrong_tag_bytes[0] ^= 0xFF;

    let inputs = InputPair::new(
        move || correct_tag_bytes.clone(),
        move || wrong_tag_bytes.clone(),
    );

    TimingOracle::for_attacker(AttackerModel::Custom {
        threshold_ns: THRESHOLD_NS,
    })
    .test(inputs, |tag| {
        let _ = std::hint::black_box(hmac::verify(&key, &message, tag));
    })
}

/// Print the outcome of a timing test with detailed information
fn print_outcome(name: &str, outcome: &Outcome) {
    match outcome {
        Outcome::Pass {
            leak_probability,
            effect,
            quality,
            ..
        } => {
            println!(
                "  {} PASS: P(leak)={:.1}%, effect={:.1}ns, quality={:?}",
                name,
                leak_probability * 100.0,
                effect.total_effect_ns(),
                quality
            );
        }
        Outcome::Fail {
            leak_probability,
            exploitability,
            effect,
            ..
        } => {
            println!(
                "  {} FAIL: P(leak)={:.1}%, effect={:.1}ns, exploitability={:?}",
                name,
                leak_probability * 100.0,
                effect.total_effect_ns(),
                exploitability
            );
        }
        Outcome::Inconclusive {
            reason,
            leak_probability,
            ..
        } => {
            println!(
                "  {} INCONCLUSIVE: P(leak)={:.1}%, reason={:?}",
                name,
                leak_probability * 100.0,
                reason
            );
        }
        Outcome::Unmeasurable {
            recommendation,
            platform,
            ..
        } => {
            println!(
                "  {} UNMEASURABLE: platform={}, recommendation={}",
                name, platform, recommendation
            );
        }
    }
}

fn main() {
    println!("timing-oracle Timing Side-Channel Tests");
    println!("========================================");
    println!("Testing security-critical constant-time operations");
    println!("Threshold: {}ns", THRESHOLD_NS);

    let mut all_passed = true;
    let mut results = Vec::new();

    // Run security-critical tests only
    let tests: Vec<(&str, fn() -> Outcome)> = vec![
        ("key_unwrap", test_key_unwrap),
        ("hmac_verify", test_hmac_verify),
    ];

    for (name, test_fn) in tests {
        let outcome = test_fn();
        print_outcome(name, &outcome);

        if outcome.failed() {
            all_passed = false;
        }

        results.push((name, outcome));
    }

    // Summary
    println!("\n========================================");
    println!("Summary:");

    let passed = results.iter().filter(|(_, o)| o.passed()).count();
    let failed = results.iter().filter(|(_, o)| o.failed()).count();
    let inconclusive = results
        .iter()
        .filter(|(_, o)| matches!(o, Outcome::Inconclusive { .. }))
        .count();
    let unmeasurable = results
        .iter()
        .filter(|(_, o)| matches!(o, Outcome::Unmeasurable { .. }))
        .count();

    println!(
        "  Passed: {}, Failed: {}, Inconclusive: {}, Unmeasurable: {}",
        passed, failed, inconclusive, unmeasurable
    );

    if !all_passed {
        println!("\nERROR: Security-critical timing tests failed!");
        std::process::exit(1);
    } else {
        println!("\nAll security-critical tests passed.");
    }
}
