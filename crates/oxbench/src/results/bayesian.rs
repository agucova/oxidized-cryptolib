//! Bayesian statistical analysis for benchmark comparisons.
//!
//! Provides proper statistical inference for benchmark results using
//! Bayesian methods with uninformative priors. Key features:
//!
//! - Direct probability statements: "92% probability FUSE is faster"
//! - ROPE (Region of Practical Equivalence) analysis
//! - Credible intervals with intuitive interpretation
//! - Handles small samples gracefully

use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use serde::Serialize;
use statrs::distribution::{ContinuousCDF, StudentsT};
use std::time::Duration;

/// Bayesian comparison between two implementations
#[derive(Debug, Clone, Serialize)]
pub struct BayesianComparison {
    /// Name of implementation A (the one we're testing)
    pub impl_a: String,
    /// Name of implementation B (the baseline/competitor)
    pub impl_b: String,

    // --- Core probabilities ---
    /// P(A is faster than B) - probability that μ_a < μ_b
    pub prob_a_faster: f64,

    /// P(A is meaningfully faster) - probability of >ROPE difference
    /// ROPE = Region of Practical Equivalence (default: 5%)
    pub prob_practically_faster: f64,

    /// P(A and B are practically equivalent) - both within ROPE
    pub prob_equivalent: f64,

    // --- Effect size ---
    /// Expected speedup ratio: E[μ_b / μ_a]
    /// >1.0 means A is faster, <1.0 means B is faster
    pub speedup_ratio: f64,

    /// 95% credible interval for speedup ratio (low, high)
    pub speedup_ci_low: f64,
    pub speedup_ci_high: f64,

    // --- Individual implementation stats ---
    pub mean_a_ns: f64,
    pub mean_b_ns: f64,
    pub ci_a_low_ns: f64,
    pub ci_a_high_ns: f64,
    pub ci_b_low_ns: f64,
    pub ci_b_high_ns: f64,
}

/// Configuration for Bayesian analysis
#[derive(Debug, Clone)]
pub struct BayesianConfig {
    /// Region of Practical Equivalence as a fraction (default: 0.05 = 5%)
    /// Differences smaller than this are considered "practically equivalent"
    pub rope_fraction: f64,

    /// Number of Monte Carlo samples for ratio CI calculation
    pub mc_samples: usize,

    /// Credible interval level (default: 0.95)
    pub ci_level: f64,

    /// Random seed for reproducibility
    pub seed: u64,
}

impl Default for BayesianConfig {
    fn default() -> Self {
        Self {
            rope_fraction: 0.05, // 5% ROPE
            mc_samples: 10_000,
            ci_level: 0.95,
            seed: 12345,
        }
    }
}

/// Sufficient statistics for a sample
#[derive(Debug, Clone, Copy)]
struct SampleStats {
    n: usize,
    mean: f64,
    variance: f64,
    std_err: f64, // Standard error of the mean
}

impl SampleStats {
    fn from_samples(samples: &[f64]) -> Self {
        let n = samples.len();
        if n < 2 {
            return Self {
                n,
                mean: samples.first().copied().unwrap_or(0.0),
                variance: 0.0,
                std_err: 0.0,
            };
        }

        let mean = samples.iter().sum::<f64>() / n as f64;
        let variance = samples
            .iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>()
            / (n - 1) as f64; // Bessel's correction
        let std_err = (variance / n as f64).sqrt();

        Self {
            n,
            mean,
            variance,
            std_err,
        }
    }

    /// Degrees of freedom for t-distribution
    fn df(&self) -> f64 {
        (self.n.saturating_sub(1)) as f64
    }
}

/// Compute Bayesian comparison between two sets of Duration samples
///
/// # Arguments
/// * `samples_a` - Duration samples from implementation A
/// * `samples_b` - Duration samples from implementation B
/// * `impl_a_name` - Display name for A
/// * `impl_b_name` - Display name for B
/// * `config` - Analysis configuration
pub fn bayesian_compare(
    samples_a: &[Duration],
    samples_b: &[Duration],
    impl_a_name: &str,
    impl_b_name: &str,
    config: &BayesianConfig,
) -> BayesianComparison {
    // Convert to nanoseconds for numerical stability
    let ns_a: Vec<f64> = samples_a.iter().map(|d| d.as_nanos() as f64).collect();
    let ns_b: Vec<f64> = samples_b.iter().map(|d| d.as_nanos() as f64).collect();

    bayesian_compare_ns(&ns_a, &ns_b, impl_a_name, impl_b_name, config)
}

/// Compute Bayesian comparison between two sets of f64 samples (in nanoseconds)
pub fn bayesian_compare_ns(
    samples_a: &[f64],
    samples_b: &[f64],
    impl_a_name: &str,
    impl_b_name: &str,
    config: &BayesianConfig,
) -> BayesianComparison {
    let stats_a = SampleStats::from_samples(samples_a);
    let stats_b = SampleStats::from_samples(samples_b);

    // Handle edge cases
    if stats_a.n < 2 || stats_b.n < 2 {
        return BayesianComparison {
            impl_a: impl_a_name.to_string(),
            impl_b: impl_b_name.to_string(),
            prob_a_faster: 0.5,
            prob_practically_faster: 0.0,
            prob_equivalent: 1.0,
            speedup_ratio: 1.0,
            speedup_ci_low: 0.5,
            speedup_ci_high: 2.0,
            mean_a_ns: stats_a.mean,
            mean_b_ns: stats_b.mean,
            ci_a_low_ns: stats_a.mean,
            ci_a_high_ns: stats_a.mean,
            ci_b_low_ns: stats_b.mean,
            ci_b_high_ns: stats_b.mean,
        };
    }

    // --- Credible intervals for individual means ---
    let (ci_a_low, ci_a_high) = compute_mean_ci(&stats_a, config.ci_level);
    let (ci_b_low, ci_b_high) = compute_mean_ci(&stats_b, config.ci_level);

    // --- Probability calculations via Welch's approximation ---
    // For the difference of means (μ_a - μ_b), we use a t-distribution
    // with Welch-Satterthwaite degrees of freedom

    let diff_mean = stats_a.mean - stats_b.mean;
    let diff_var = stats_a.variance / stats_a.n as f64 + stats_b.variance / stats_b.n as f64;
    let diff_std = diff_var.sqrt();

    let df = welch_satterthwaite_df(&stats_a, &stats_b);

    // P(A faster) = P(μ_a < μ_b) = P(diff < 0)
    let (prob_a_faster, prob_practically_faster, prob_equivalent) = if diff_std > 1e-10 && df > 0.0
    {
        let t_dist = StudentsT::new(0.0, 1.0, df).unwrap();
        let t_stat = diff_mean / diff_std;
        let prob_a_faster = t_dist.cdf(-t_stat);

        // --- ROPE analysis ---
        // ROPE boundaries: difference is within ±rope_fraction of baseline mean
        let rope_width = config.rope_fraction * stats_b.mean;

        // P(practically faster) = P(diff < -rope_width)
        let t_rope_lower = (-rope_width - diff_mean) / diff_std;
        let prob_practically_faster = t_dist.cdf(t_rope_lower);

        // P(equivalent) = P(-rope_width < diff < rope_width)
        let t_upper = (rope_width - diff_mean) / diff_std;
        let t_lower = (-rope_width - diff_mean) / diff_std;
        let prob_equivalent = t_dist.cdf(t_upper) - t_dist.cdf(t_lower);

        (prob_a_faster, prob_practically_faster, prob_equivalent)
    } else {
        // No variance - can't distinguish
        (0.5, 0.0, 1.0)
    };

    // --- Speedup ratio via Monte Carlo ---
    let (speedup_ratio, speedup_ci_low, speedup_ci_high) =
        compute_speedup_ratio_mc(&stats_a, &stats_b, config);

    BayesianComparison {
        impl_a: impl_a_name.to_string(),
        impl_b: impl_b_name.to_string(),
        prob_a_faster,
        prob_practically_faster,
        prob_equivalent,
        speedup_ratio,
        speedup_ci_low,
        speedup_ci_high,
        mean_a_ns: stats_a.mean,
        mean_b_ns: stats_b.mean,
        ci_a_low_ns: ci_a_low,
        ci_a_high_ns: ci_a_high,
        ci_b_low_ns: ci_b_low,
        ci_b_high_ns: ci_b_high,
    }
}

/// Compute credible interval for a mean using t-distribution
fn compute_mean_ci(stats: &SampleStats, level: f64) -> (f64, f64) {
    if stats.n < 2 || stats.std_err < 1e-10 {
        return (stats.mean, stats.mean);
    }

    let alpha = 1.0 - level;
    let df = stats.df();
    if df <= 0.0 {
        return (stats.mean, stats.mean);
    }

    let t_dist = StudentsT::new(0.0, 1.0, df).unwrap();

    // Two-tailed: find t such that P(-t < T < t) = level
    let t_crit = t_dist.inverse_cdf(1.0 - alpha / 2.0);

    let margin = t_crit * stats.std_err;
    (stats.mean - margin, stats.mean + margin)
}

/// Welch-Satterthwaite degrees of freedom for unequal variances
fn welch_satterthwaite_df(a: &SampleStats, b: &SampleStats) -> f64 {
    let var_a_n = a.variance / a.n as f64;
    let var_b_n = b.variance / b.n as f64;

    let numerator = (var_a_n + var_b_n).powi(2);
    let denominator =
        var_a_n.powi(2) / (a.n.saturating_sub(1)) as f64 + var_b_n.powi(2) / (b.n.saturating_sub(1)) as f64;

    if denominator < 1e-10 {
        return 1.0;
    }

    numerator / denominator
}

/// Compute speedup ratio E[μ_b/μ_a] and CI via Monte Carlo
///
/// Ratio of means doesn't have a closed-form distribution,
/// so we sample from the posterior and compute the ratio.
fn compute_speedup_ratio_mc(
    stats_a: &SampleStats,
    stats_b: &SampleStats,
    config: &BayesianConfig,
) -> (f64, f64, f64) {
    if stats_a.n < 2 || stats_b.n < 2 || stats_a.std_err < 1e-10 || stats_b.std_err < 1e-10 {
        let ratio = if stats_a.mean > 1e-10 {
            stats_b.mean / stats_a.mean
        } else {
            1.0
        };
        return (ratio, ratio * 0.5, ratio * 2.0);
    }

    let mut rng = ChaCha8Rng::seed_from_u64(config.seed);

    // Sample from posterior of each mean
    // μ | data ~ t(df, x̄, s/√n)
    let df_a = stats_a.df();
    let df_b = stats_b.df();

    if df_a <= 0.0 || df_b <= 0.0 {
        let ratio = stats_b.mean / stats_a.mean.max(1e-10);
        return (ratio, ratio * 0.5, ratio * 2.0);
    }

    let t_a = StudentsT::new(stats_a.mean, stats_a.std_err, df_a).unwrap();
    let t_b = StudentsT::new(stats_b.mean, stats_b.std_err, df_b).unwrap();

    let mut ratios: Vec<f64> = Vec::with_capacity(config.mc_samples);

    for _ in 0..config.mc_samples {
        // Sample from posteriors using inverse CDF
        let u_a: f64 = rng.random();
        let u_b: f64 = rng.random();

        let mu_a = t_a.inverse_cdf(u_a.clamp(0.001, 0.999));
        let mu_b = t_b.inverse_cdf(u_b.clamp(0.001, 0.999));

        // Compute ratio (skip if μ_a is too close to zero)
        if mu_a.abs() > 1e-10 {
            let ratio = mu_b / mu_a;
            // Filter out extreme outliers that can occur with heavy-tailed t
            if ratio > 0.01 && ratio < 100.0 {
                ratios.push(ratio);
            }
        }
    }

    if ratios.is_empty() {
        let ratio = stats_b.mean / stats_a.mean.max(1e-10);
        return (ratio, ratio * 0.5, ratio * 2.0);
    }

    // Sort for percentile calculation
    ratios.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let mean_ratio = ratios.iter().sum::<f64>() / ratios.len() as f64;

    // Credible interval
    let alpha = 1.0 - config.ci_level;
    let lo_idx = ((alpha / 2.0) * ratios.len() as f64) as usize;
    let hi_idx = ((1.0 - alpha / 2.0) * ratios.len() as f64) as usize;

    let ci_low = ratios.get(lo_idx).copied().unwrap_or(mean_ratio);
    let ci_high = ratios
        .get(hi_idx.min(ratios.len().saturating_sub(1)))
        .copied()
        .unwrap_or(mean_ratio);

    (mean_ratio, ci_low, ci_high)
}

impl BayesianComparison {
    /// Format a summary suitable for terminal output
    pub fn format_summary(&self) -> String {
        let winner = if self.prob_a_faster > 0.5 {
            &self.impl_a
        } else {
            &self.impl_b
        };

        let prob = if self.prob_a_faster > 0.5 {
            self.prob_a_faster
        } else {
            1.0 - self.prob_a_faster
        };

        let practical_assessment = if self.prob_equivalent > 0.9 {
            "practically equivalent".to_string()
        } else if self.prob_practically_faster > 0.9 {
            format!("{} is meaningfully faster", self.impl_a)
        } else if self.prob_practically_faster < 0.1 && self.prob_a_faster < 0.5 {
            format!("{} is meaningfully faster", self.impl_b)
        } else {
            "difference may not be practically significant".to_string()
        };

        format!(
            "{:.1}% probability {} is faster\n\
             Speedup: {:.2}x [{:.2}x - {:.2}x]\n\
             Assessment: {}",
            prob * 100.0,
            winner,
            self.speedup_ratio,
            self.speedup_ci_low,
            self.speedup_ci_high,
            practical_assessment
        )
    }

    /// Should we claim A is faster? (conservative threshold)
    ///
    /// Requires both:
    /// - >95% probability A has lower latency
    /// - >80% probability the difference exceeds ROPE (practically significant)
    pub fn can_claim_a_faster(&self) -> bool {
        self.prob_a_faster > 0.95 && self.prob_practically_faster > 0.80
    }

    /// Should we claim B is faster? (conservative threshold)
    pub fn can_claim_b_faster(&self) -> bool {
        self.prob_a_faster < 0.05 && self.prob_practically_faster < 0.20
    }

    /// Get winner name and confidence level
    pub fn winner(&self) -> Option<(&str, f64)> {
        if self.can_claim_a_faster() {
            Some((&self.impl_a, self.prob_a_faster))
        } else if self.can_claim_b_faster() {
            Some((&self.impl_b, 1.0 - self.prob_a_faster))
        } else {
            None
        }
    }

    /// Get the assessment string for display
    pub fn assessment(&self) -> &'static str {
        if self.prob_equivalent > 0.9 {
            "Practically equivalent"
        } else if self.can_claim_a_faster() {
            "A is faster with high confidence"
        } else if self.can_claim_b_faster() {
            "B is faster with high confidence"
        } else if self.prob_a_faster > 0.8 {
            "A likely faster (moderate confidence)"
        } else if self.prob_a_faster < 0.2 {
            "B likely faster (moderate confidence)"
        } else {
            "Difference not statistically significant"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dur(ns: u64) -> Duration {
        Duration::from_nanos(ns)
    }

    #[test]
    fn test_clearly_faster() {
        // A is clearly faster (lower latency)
        let samples_a: Vec<Duration> = vec![dur(100), dur(105), dur(98), dur(102), dur(101)];
        let samples_b: Vec<Duration> = vec![dur(200), dur(210), dur(195), dur(205), dur(198)];

        let result = bayesian_compare(
            &samples_a,
            &samples_b,
            "FUSE",
            "Cryptomator",
            &BayesianConfig::default(),
        );

        assert!(
            result.prob_a_faster > 0.99,
            "prob_a_faster was {}",
            result.prob_a_faster
        );
        assert!(
            result.speedup_ratio > 1.8,
            "speedup was {}",
            result.speedup_ratio
        );
        assert!(result.can_claim_a_faster());
    }

    #[test]
    fn test_equivalent() {
        // A and B are similar
        let samples_a: Vec<Duration> = vec![dur(100), dur(102), dur(99), dur(101), dur(100)];
        let samples_b: Vec<Duration> = vec![dur(101), dur(103), dur(100), dur(102), dur(101)];

        let result = bayesian_compare(
            &samples_a,
            &samples_b,
            "FUSE",
            "Cryptomator",
            &BayesianConfig::default(),
        );

        // Neither should be claimable as faster
        assert!(!result.can_claim_a_faster());
        assert!(!result.can_claim_b_faster());
        // High probability of equivalence
        assert!(
            result.prob_equivalent > 0.5,
            "prob_equivalent was {}",
            result.prob_equivalent
        );
    }

    #[test]
    fn test_small_sample_wide_ci() {
        // With very few samples, CI should be wide
        let samples_a: Vec<Duration> = vec![dur(100), dur(120), dur(90)];
        let samples_b: Vec<Duration> = vec![dur(150), dur(180), dur(130)];

        let result = bayesian_compare(&samples_a, &samples_b, "A", "B", &BayesianConfig::default());

        // CI should be reasonably wide for 3 samples
        let ci_width = result.speedup_ci_high - result.speedup_ci_low;
        assert!(ci_width > 0.2, "CI too narrow for 3 samples: {}", ci_width);
    }

    #[test]
    fn test_format_summary() {
        let samples_a: Vec<Duration> = vec![dur(100), dur(105), dur(98), dur(102), dur(101)];
        let samples_b: Vec<Duration> = vec![dur(200), dur(210), dur(195), dur(205), dur(198)];

        let result = bayesian_compare(
            &samples_a,
            &samples_b,
            "FUSE",
            "Cryptomator",
            &BayesianConfig::default(),
        );

        let summary = result.format_summary();
        assert!(summary.contains("FUSE"));
        assert!(summary.contains("faster"));
    }

    #[test]
    fn test_real_world_latencies() {
        // More realistic latencies in milliseconds (as nanoseconds)
        let samples_a: Vec<Duration> = (0..50)
            .map(|i| Duration::from_micros(4000 + (i % 10) * 50))
            .collect();
        let samples_b: Vec<Duration> = (0..50)
            .map(|i| Duration::from_micros(5000 + (i % 10) * 60))
            .collect();

        let result = bayesian_compare(
            &samples_a,
            &samples_b,
            "FUSE",
            "Cryptomator",
            &BayesianConfig::default(),
        );

        // With 50 samples and clear difference, should have high confidence
        assert!(
            result.prob_a_faster > 0.99,
            "prob_a_faster was {}",
            result.prob_a_faster
        );
        // Speedup should be around 1.25x
        assert!(result.speedup_ratio > 1.1 && result.speedup_ratio < 1.5);
    }
}
