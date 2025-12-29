//! Live progress reporting during benchmark execution.

use indicatif::{ProgressBar, ProgressStyle};
use std::collections::VecDeque;
use std::time::Duration;

/// Manages live terminal output during benchmark execution.
///
/// Shows a spinner with current time estimate, progress bar, and ETA.
/// Example output:
/// ```text
/// Benchmark: fuse / read_4KB
///   ⠋ Current estimate: 2.45 ms    ████████░░░░░░░░░░░░  ETA 00:00:12
/// ```
pub struct LiveProgressReporter {
    /// The active progress bar.
    progress: ProgressBar,
    /// Header line (already printed).
    #[allow(dead_code)]
    header: String,
    /// Rolling window of recent samples for live estimate.
    recent_samples: VecDeque<Duration>,
    /// Maximum samples to keep for rolling average.
    window_size: usize,
    /// Total expected iterations.
    total_iterations: usize,
    /// Completed iterations.
    completed: usize,
    /// Whether color is enabled.
    color: bool,
}

impl LiveProgressReporter {
    /// Create a new progress reporter for a benchmark.
    ///
    /// Prints the header line and initializes the progress bar.
    pub fn new(
        benchmark_name: &str,
        impl_name: &str,
        iterations: usize,
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
            format!("Benchmark: {} / {}", impl_name, benchmark_name)
        };
        println!("{}", header);

        // Create the progress bar with hyperfine-style template
        let progress = ProgressBar::new(iterations as u64);

        let style = if color {
            ProgressStyle::default_bar()
                .template("  {spinner:.cyan} Current estimate: {msg:<12}  {bar:20.cyan/dim} ETA {eta}")
                .expect("valid template")
                .progress_chars("█▓░")
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
        } else {
            ProgressStyle::default_bar()
                .template("  {spinner} Current estimate: {msg:<12}  {bar:20} ETA {eta}")
                .expect("valid template")
                .progress_chars("█▓░")
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
        };

        progress.set_style(style);
        progress.set_message("measuring...");
        progress.enable_steady_tick(Duration::from_millis(100));

        Self {
            progress,
            header: header.clone(),
            recent_samples: VecDeque::with_capacity(20),
            window_size: 20,
            total_iterations: iterations,
            completed: 0,
            color,
        }
    }

    /// Called after each iteration to update the spinner and estimate.
    pub fn tick(&mut self, sample: Duration) {
        self.completed += 1;

        // Update rolling window
        if self.recent_samples.len() >= self.window_size {
            self.recent_samples.pop_front();
        }
        self.recent_samples.push_back(sample);

        // Calculate rolling average
        let avg = self.rolling_average();
        let estimate = super::format::format_duration(avg);

        self.progress.set_message(estimate);
        self.progress.set_position(self.completed as u64);
    }

    /// Get the rolling average of recent samples.
    fn rolling_average(&self) -> Duration {
        if self.recent_samples.is_empty() {
            return Duration::ZERO;
        }
        let sum: Duration = self.recent_samples.iter().sum();
        sum / self.recent_samples.len() as u32
    }

    /// Finish the progress bar and clear the line.
    ///
    /// Returns the final rolling average for reference.
    pub fn finish(self) -> Duration {
        let avg = self.rolling_average();
        self.progress.finish_and_clear();
        avg
    }

    /// Abort with an error message.
    #[allow(dead_code)]
    pub fn abort(self, message: &str) {
        use owo_colors::OwoColorize;

        self.progress.finish_and_clear();
        if self.color {
            eprintln!("  {} {}", "Error:".red().bold(), message);
        } else {
            eprintln!("  Error: {}", message);
        }
    }

    /// Get the number of completed iterations.
    #[allow(dead_code)]
    pub fn completed(&self) -> usize {
        self.completed
    }

    /// Get the total number of iterations.
    #[allow(dead_code)]
    pub fn total(&self) -> usize {
        self.total_iterations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rolling_average() {
        let mut reporter = LiveProgressReporter {
            progress: ProgressBar::hidden(),
            header: String::new(),
            recent_samples: VecDeque::new(),
            window_size: 5,
            total_iterations: 10,
            completed: 0,
            color: false,
        };

        // Empty should return zero
        assert_eq!(reporter.rolling_average(), Duration::ZERO);

        // Add some samples
        reporter.recent_samples.push_back(Duration::from_millis(10));
        reporter.recent_samples.push_back(Duration::from_millis(20));
        reporter.recent_samples.push_back(Duration::from_millis(30));

        // Average should be (10 + 20 + 30) / 3 = 20ms
        assert_eq!(reporter.rolling_average(), Duration::from_millis(20));
    }
}
