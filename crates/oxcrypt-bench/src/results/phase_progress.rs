//! Phase-aware progress reporting for workloads with multiple internal phases.
//!
//! This module provides `PhaseProgressReporter` which displays fine-grained
//! progress during workload execution, showing both the current phase and
//! item-level progress within each phase.
//!
//! Example output:
//! ```text
//! Benchmark: fuse / Chinook Database
//!   Phase 3/6: Aggregation queries (15/30)
//!   ⠋ ██████░░░░░░░░░░░░░░  ETA 00:00:08
//! ```

use crate::bench::PhaseProgress;
use indicatif::{ProgressBar, ProgressStyle};
use std::cell::RefCell;
use std::time::{Duration, Instant};

/// Internal mutable state for the reporter.
struct ReporterState {
    /// Current phase index (0-based).
    current_phase: usize,
    /// Current phase name.
    current_phase_name: String,
    /// Items completed so far (cumulative across phases for ETA).
    cumulative_items: usize,
    /// Total items across all phases (estimated for ETA).
    estimated_total_items: usize,
}

/// Progress reporter for workloads with multiple internal phases.
///
/// Unlike `LiveProgressReporter` which tracks iterations, this reporter
/// tracks phase progress and items within each phase, providing more
/// accurate ETA calculations for complex workloads.
///
/// Uses interior mutability via `RefCell` so that `update()` can be called
/// from `Fn` callbacks (not just `FnMut`).
pub struct PhaseProgressReporter {
    /// The progress bar for item-level progress.
    progress: ProgressBar,
    /// Whether color output is enabled.
    color: bool,
    /// Start time for ETA calculation.
    start_time: Instant,
    /// Mutable state wrapped in RefCell for interior mutability.
    state: RefCell<ReporterState>,
}

impl PhaseProgressReporter {
    /// Create a new phase progress reporter.
    ///
    /// Prints the benchmark header and initializes the progress bar.
    /// The `_total_phases` parameter is reserved for future use (sub-bar display).
    pub fn new(
        benchmark_name: &str,
        impl_name: &str,
        _total_phases: usize,
        color: bool,
    ) -> Self {
        use owo_colors::OwoColorize;

        // Print the benchmark header
        let header = if color {
            format!(
                "{}: {} / {}",
                "Benchmark".bold(),
                impl_name.cyan(),
                benchmark_name
            )
        } else {
            format!("Benchmark: {impl_name} / {benchmark_name}")
        };
        println!("{header}");

        // Create progress bar - we'll update the length dynamically
        let progress = ProgressBar::new(100);

        let style = if color {
            ProgressStyle::default_bar()
                .template("  {spinner:.cyan} {msg}\n  {bar:40.cyan/dim}  ETA {eta}")
                .expect("valid template")
                .progress_chars("█▓░")
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
        } else {
            ProgressStyle::default_bar()
                .template("  {spinner} {msg}\n  {bar:40}  ETA {eta}")
                .expect("valid template")
                .progress_chars("█▓░")
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
        };

        progress.set_style(style);
        progress.set_message("Starting...");
        progress.enable_steady_tick(Duration::from_millis(100));

        Self {
            progress,
            color,
            start_time: Instant::now(),
            state: RefCell::new(ReporterState {
                current_phase: 0,
                current_phase_name: String::new(),
                cumulative_items: 0,
                estimated_total_items: 0,
            }),
        }
    }

    /// Update progress from a `PhaseProgress` callback.
    ///
    /// This should be called periodically by the workload to update the display.
    /// Uses interior mutability so it can be called from `Fn` callbacks.
    pub fn update(&self, progress: &PhaseProgress) {
        use owo_colors::OwoColorize;

        let mut state = self.state.borrow_mut();

        // Track phase changes
        if progress.phase_index != state.current_phase {
            // Accumulate items from completed phases for overall ETA
            state.current_phase = progress.phase_index;
        }

        state.current_phase_name = progress.phase_name.to_string();

        // Format the phase status message
        let phase_info = format!(
            "Phase {}/{}: {}",
            progress.phase_index + 1,
            progress.total_phases,
            progress.phase_name
        );

        let message = if let (Some(completed), Some(total)) =
            (progress.items_completed, progress.items_total)
        {
            // Update progress bar length and position based on items
            self.progress.set_length(total as u64);
            self.progress.set_position(completed as u64);

            // Update estimated total items for better ETA
            // Estimate: items so far + remaining phases * current phase items
            let remaining_phases = progress.total_phases.saturating_sub(progress.phase_index + 1);
            let estimated_remaining = remaining_phases * total;
            state.estimated_total_items =
                state.cumulative_items + completed + estimated_remaining + (total - completed);

            if self.color {
                format!(
                    "{} ({}/{})",
                    phase_info,
                    completed.to_string().green(),
                    total
                )
            } else {
                format!("{phase_info} ({completed}/{total})")
            }
        } else {
            // No item counts, just show phase
            self.progress.set_length(progress.total_phases as u64);
            self.progress.set_position(progress.phase_index as u64);
            phase_info
        };

        self.progress.set_message(message);
    }

    /// Finish the progress bar and clear the display.
    ///
    /// Returns the total elapsed time.
    pub fn finish(self) -> Duration {
        self.progress.finish_and_clear();
        self.start_time.elapsed()
    }

    /// Abort with an error message.
    #[allow(dead_code)]
    pub fn abort(self, message: &str) {
        use owo_colors::OwoColorize;

        self.progress.finish_and_clear();
        if self.color {
            eprintln!("  {} {}", "Error:".red().bold(), message);
        } else {
            eprintln!("  Error: {message}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench::PhaseProgress;

    #[test]
    fn test_phase_progress_reporter_hidden() {
        // Test with hidden progress bar (no TTY)
        let reporter = PhaseProgressReporter {
            progress: ProgressBar::hidden(),
            color: false,
            start_time: Instant::now(),
            state: RefCell::new(ReporterState {
                current_phase: 0,
                current_phase_name: String::new(),
                cumulative_items: 0,
                estimated_total_items: 0,
            }),
        };

        // Simulate phase 1 progress
        reporter.update(&PhaseProgress {
            phase_name: "Index lookups",
            phase_index: 0,
            total_phases: 3,
            items_completed: Some(50),
            items_total: Some(100),
        });

        assert_eq!(reporter.state.borrow().current_phase, 0);
        assert_eq!(reporter.state.borrow().current_phase_name, "Index lookups");

        // Simulate phase 2
        reporter.update(&PhaseProgress {
            phase_name: "Join queries",
            phase_index: 1,
            total_phases: 3,
            items_completed: Some(25),
            items_total: Some(50),
        });

        assert_eq!(reporter.state.borrow().current_phase, 1);
        assert_eq!(reporter.state.borrow().current_phase_name, "Join queries");

        let _elapsed = reporter.finish();
    }

    #[test]
    fn test_phase_progress_without_items() {
        let reporter = PhaseProgressReporter {
            progress: ProgressBar::hidden(),
            color: false,
            start_time: Instant::now(),
            state: RefCell::new(ReporterState {
                current_phase: 0,
                current_phase_name: String::new(),
                cumulative_items: 0,
                estimated_total_items: 0,
            }),
        };

        // Progress without item counts
        reporter.update(&PhaseProgress {
            phase_name: "Complex analytics",
            phase_index: 0,
            total_phases: 2,
            items_completed: None,
            items_total: None,
        });

        assert_eq!(
            reporter.state.borrow().current_phase_name,
            "Complex analytics"
        );
    }
}
