//! Git Workflow Workload
//!
//! Uses real libgit2 to simulate git operations on ripgrep source code:
//! - git init, git add, git commit, git status, git log
//! - Heavy on metadata operations (stat storms), directory traversal, and read-after-write patterns.
//!
//! Downloads ripgrep source (~1MB compressed, expands to realistic Rust project)
//! for testing repository operations on encrypted storage.

// Allow helper method patterns, debug formatting, and recursive helpers
#![allow(clippy::unused_self, clippy::unnecessary_debug_formatting, clippy::self_only_used_in_recursion)]

use crate::assets::{AssetDownloader, manifest::GIT_RIPGREP};
use crate::bench::{Benchmark, PhaseProgress, PhaseProgressCallback};
use crate::bench::workloads::WorkloadConfig;
use crate::config::OperationType;
use anyhow::{anyhow, Context, Result};
use git2::{IndexAddOption, Repository, Signature};
use oxcrypt_mount::safe_sync;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zip::ZipArchive;

// Workload parameters
const FILES_TO_MODIFY: usize = 20;
const FILES_TO_CREATE: usize = 10;
const FILES_TO_DELETE: usize = 5;
const NUM_COMMITS: usize = 5;
const LOG_ENTRIES_TO_READ: usize = 20;

/// Git workload phases for progress reporting.
const GIT_PHASES: &[&str] = &[
    "git status",
    "Modify tree",
    "git status after",
    "git add & commit",
    "git log",
    "git diff",
];

/// Git Workflow Workload using real libgit2.
///
/// Phases:
/// 1. git init - Initialize a real git repository with ripgrep source
/// 2. Initial commit - Add all files and commit
/// 3. git status - Check working tree status (metadata heavy)
/// 4. Modify working tree - Modify, create, and delete files
/// 5. git add & commit - Stage changes and create commits
/// 6. git log - Walk commit history
///
/// Uses ripgrep source code (~500 files) for realistic Rust project structure.
pub struct GitWorkload {
    config: WorkloadConfig,
    seed: u64,
}

impl GitWorkload {
    /// Create a new git workload.
    pub fn new(config: WorkloadConfig) -> Self {
        Self {
            config,
            seed: 0x617_C0DE,
        }
    }

    #[allow(clippy::unused_self)]  // Part of workload API
    fn workload_dir(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        mount_point.join(format!("bench_git_workload_{}_iter{}", self.config.session_id, iteration))
    }

    fn repo_path(&self, mount_point: &Path, iteration: usize) -> PathBuf {
        self.workload_dir(mount_point, iteration).join("repo")
    }

    /// Create the signature for commits.
    #[allow(clippy::unused_self)]  // Helper method - kept as instance method for consistency
    fn signature(&self) -> Result<Signature<'static>> {
        Ok(Signature::now("Benchmark User", "bench@example.com")?)
    }

    /// Extract ripgrep source zip to the repo directory.
    #[allow(clippy::unused_self)]  // May access self fields in future
    fn extract_ripgrep(&self, repo_path: &Path) -> Result<()> {
        let downloader = AssetDownloader::new()?;

        // Ensure the asset is downloaded
        let zip_path = downloader.ensure(&GIT_RIPGREP)?;

        // Extract zip file
        tracing::debug!("Extracting ripgrep source to {:?}", repo_path);
        let zip_bytes = fs::read(&zip_path)
            .with_context(|| format!("Failed to read {zip_path:?}"))?;

        // Open zip archive
        let cursor = Cursor::new(zip_bytes);
        let mut archive = ZipArchive::new(cursor)
            .context("Failed to open zip archive")?;

        // Extract all files
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)
                .with_context(|| format!("Failed to read zip entry {i}"))?;
            let file_path = file.enclosed_name()
                .context("Invalid zip entry path")?;

            // Strip top-level directory (e.g., "ripgrep-14.1.0/")
            let relative_path = file_path.components().skip(1).collect::<PathBuf>();
            if relative_path.as_os_str().is_empty() {
                continue; // Skip root directory entry
            }

            let dest_path = repo_path.join(&relative_path);

            if file.is_dir() {
                // Create directory
                fs::create_dir_all(&dest_path)?;
            } else {
                // Create parent directory if needed
                if let Some(parent) = dest_path.parent() {
                    fs::create_dir_all(parent)?;
                }

                // Extract file
                let mut outfile = File::create(&dest_path)
                    .with_context(|| format!("Failed to create {dest_path:?}"))?;
                std::io::copy(&mut file, &mut outfile)
                    .with_context(|| format!("Failed to extract {file_path:?}"))?;

                // Set permissions (Unix only)
                #[cfg(unix)]
                if let Some(mode) = file.unix_mode() {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&dest_path, fs::Permissions::from_mode(mode))?;
                }
            }
        }

        tracing::debug!("Extracted ripgrep successfully");
        Ok(())
    }

    /// Collect all file paths in the repository (relative paths).
    fn collect_repo_files(&self, repo_path: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        self.walk_files(repo_path, repo_path, &mut files)?;
        Ok(files)
    }

    #[allow(clippy::self_only_used_in_recursion)]  // self needed for recursive call
    fn walk_files(&self, base: &Path, dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            // Skip .git directory
            if path.file_name().is_some_and(|n| n == ".git") {
                continue;
            }

            if path.is_dir() {
                self.walk_files(base, &path, files)?;
            } else if path.is_file() {
                // Store relative path
                if let Ok(rel) = path.strip_prefix(base) {
                    files.push(rel.to_path_buf());
                }
            }
        }
        Ok(())
    }

    /// Generate new file content for created files.
    fn generate_new_file(&self, rng: &mut ChaCha8Rng, index: usize) -> Vec<u8> {
        let size = 512 + rng.random_range(0..2048);
        let mut content = Vec::with_capacity(size);

        writeln!(content, "// Benchmark generated file {index}")
            .expect("Failed to write to in-memory buffer - system OOM");
        writeln!(content, "// This file was created during the git workload benchmark")
            .expect("Failed to write to in-memory buffer - system OOM");
        writeln!(content)
            .expect("Failed to write to in-memory buffer - system OOM");

        while content.len() < size {
            let line: String = (0..60)
                .map(|_| (b'a' + (rng.random::<u8>() % 26)) as char)
                .collect();
            writeln!(content, "// {line}")
                .expect("Failed to write to in-memory buffer - system OOM");
        }

        content.truncate(size);
        content
    }
}

impl Default for GitWorkload {
    fn default() -> Self {
        Self::new(WorkloadConfig::default())
    }
}

impl Benchmark for GitWorkload {
    fn name(&self) -> &'static str {
        "Git Workflow"
    }

    fn operation(&self) -> OperationType {
        OperationType::GitWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("source".to_string(), "ripgrep-14.1.0".to_string());
        params.insert("modify".to_string(), FILES_TO_MODIFY.to_string());
        params.insert("create".to_string(), FILES_TO_CREATE.to_string());
        params.insert("delete".to_string(), FILES_TO_DELETE.to_string());
        params.insert("commits".to_string(), NUM_COMMITS.to_string());
        params
    }

    fn setup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        // Create workload directory
        let repo_path = self.repo_path(mount_point, iteration);
        fs::create_dir_all(&repo_path)?;

        // Extract ripgrep source
        tracing::info!("Setting up git workload with ripgrep source...");
        self.extract_ripgrep(&repo_path)?;

        // Initialize git repository
        let repo = Repository::init(&repo_path)?;

        // Configure git to avoid hardlink usage (FUSE doesn't support hardlinks)
        {
            let mut config = repo.config()?;
            // Disable auto-gc which can trigger hardlink creation during object packing
            config.set_bool("gc.auto", false)?;
            // Disable automatic pack file creation
            config.set_i32("gc.autopacklimit", 0)?;
        }

        // Stage all files
        let mut index = repo.index().context("Failed to get repo index")?;
        index.add_all(["*"].iter(), IndexAddOption::DEFAULT, None)
            .map_err(|e| anyhow!("Failed to add files to index: {} (code: {:?}, class: {:?})",
                                 e.message(), e.code(), e.class()))?;
        index.write().context("Failed to write index")?;

        // Create initial commit
        let tree_id = index.write_tree().context("Failed to write tree")?;
        tracing::debug!("Wrote tree with ID: {}", tree_id);
        let tree = repo.find_tree(tree_id)
            .context(format!("Failed to find tree {}", tree_id))?;
        let sig = self.signature()?;

        repo.commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[])
            .context("Failed to create initial commit")?;

        tracing::info!("Git workload setup complete");
        Ok(())
    }

    fn run(&self, mount_point: &Path, iteration: usize) -> Result<Duration> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);
        let start = Instant::now();

        let repo_path = self.repo_path(mount_point, iteration);
        let repo = Repository::open(&repo_path)?;

        // Collect all files in the repo
        let all_files = self.collect_repo_files(&repo_path)?;
        let num_files = all_files.len();

        tracing::debug!("Working with {} files in ripgrep repo", num_files);

        // ===== Phase 1: git status (metadata heavy) =====
        {
            // Get repository status - this triggers stat() on all tracked files
            let statuses = repo.statuses(None)?;
            std::hint::black_box(statuses.len());

            // Do it again (simulates repeated status checks)
            let statuses = repo.statuses(None)?;
            std::hint::black_box(statuses.len());
        }

        // ===== Phase 2: Modify working tree =====
        let mut indices: Vec<usize> = (0..num_files).collect();
        indices.shuffle(&mut rng);

        // Adjust counts based on actual file count
        let modify_count = FILES_TO_MODIFY.min(num_files / 3);
        let delete_count = FILES_TO_DELETE.min(num_files / 10);

        let modify_indices: Vec<usize> = indices[..modify_count].to_vec();
        let delete_indices: Vec<usize> =
            indices[modify_count..modify_count + delete_count].to_vec();

        // Modify files (append comments)
        for &idx in &modify_indices {
            let rel_path = &all_files[idx];
            let full_path = repo_path.join(rel_path);

            if full_path.exists() {
                let mut content = fs::read(&full_path)?;
                writeln!(content, "\n// Modified by benchmark at iteration {idx}")
                    .expect("Failed to write to in-memory buffer - system OOM");
                let mut file = File::create(&full_path)?;
                file.write_all(&content)?;
                safe_sync(&file)?;
            }
        }

        // Create new files in a bench_generated directory
        let gen_dir = repo_path.join("crates").join("bench_generated");
        fs::create_dir_all(&gen_dir)?;

        for i in 0..FILES_TO_CREATE {
            let filename = format!("bench_file_{i:03}.rs");
            let full_path = gen_dir.join(&filename);

            let content = self.generate_new_file(&mut rng, i);
            let mut file = File::create(&full_path)?;
            file.write_all(&content)?;
            safe_sync(&file)?;
        }

        // Delete files
        for &idx in &delete_indices {
            let rel_path = &all_files[idx];
            let full_path = repo_path.join(rel_path);
            if full_path.exists() {
                fs::remove_file(&full_path)?;
            }
        }

        // ===== Phase 3: git status after changes =====
        {
            let statuses = repo.statuses(None)?;
            std::hint::black_box(statuses.len());
        }

        // ===== Phase 4: git add & commit (multiple commits) =====
        for commit_num in 0..NUM_COMMITS {
            let mut index = repo.index()?;

            // Stage all changes
            index.add_all(["*"].iter(), IndexAddOption::DEFAULT, None)?;

            // Also update index for deleted files
            index.update_all(["*"].iter(), None)?;

            index.write()?;

            // Create commit
            let tree_id = index.write_tree()?;
            let tree = repo.find_tree(tree_id)?;
            let sig = self.signature()?;

            let head = repo.head()?;
            let parent_commit = head.peel_to_commit()?;

            repo.commit(
                Some("HEAD"),
                &sig,
                &sig,
                &format!("Benchmark commit {commit_num}"),
                &tree,
                &[&parent_commit],
            )?;

            // Make a small change for the next commit
            if commit_num < NUM_COMMITS - 1 && !modify_indices.is_empty() {
                let idx = modify_indices[commit_num % modify_indices.len()];
                let rel_path = &all_files[idx];
                let full_path = repo_path.join(rel_path);

                if full_path.exists() {
                    let mut content = fs::read(&full_path)?;
                    writeln!(content, "// Commit {commit_num} change")
                        .expect("Failed to write to in-memory buffer - system OOM");
                    let mut file = File::create(&full_path)?;
                    file.write_all(&content)?;
                    safe_sync(&file)?;
                }
            }
        }

        // ===== Phase 5: git log (walk commit history) =====
        {
            let mut revwalk = repo.revwalk()?;
            revwalk.push_head()?;

            for (count, oid) in revwalk.enumerate() {
                if count >= LOG_ENTRIES_TO_READ {
                    break;
                }

                let oid = oid?;
                let commit = repo.find_commit(oid)?;

                // Read commit metadata
                std::hint::black_box(commit.message());
                std::hint::black_box(commit.author().name());
                std::hint::black_box(commit.time().seconds());

                // Optionally read the tree (simulates git show)
                let tree = commit.tree()?;
                std::hint::black_box(tree.len());
            }
        }

        // ===== Phase 6: git diff (compare trees) =====
        {
            let head = repo.head()?;
            let head_commit = head.peel_to_commit()?;

            if let Ok(parent) = head_commit.parent(0) {
                let parent_tree = parent.tree()?;
                let head_tree = head_commit.tree()?;

                let diff = repo.diff_tree_to_tree(Some(&parent_tree), Some(&head_tree), None)?;
                std::hint::black_box(diff.stats()?.files_changed());
            }
        }

        Ok(start.elapsed())
    }

    fn cleanup(&self, mount_point: &Path, iteration: usize) -> Result<()> {
        let workload_dir = self.workload_dir(mount_point, iteration);
        if workload_dir.exists() {
            fs::remove_dir_all(&workload_dir)?;
        }
        Ok(())
    }

    fn warmup_iterations(&self) -> usize {
        1
    }

    fn requires_symlinks(&self) -> bool {
        true  // Git workload requires symlink support
    }

    fn phases(&self) -> Option<&[&'static str]> {
        Some(GIT_PHASES)
    }

    fn run_with_progress(
        &self,
        mount_point: &Path,
        iteration: usize,
        progress: Option<PhaseProgressCallback<'_>>,
    ) -> Result<Duration> {
        let report = |phase_idx: usize, items_done: Option<usize>, items_total: Option<usize>| {
            if let Some(cb) = progress {
                cb(PhaseProgress {
                    phase_name: GIT_PHASES[phase_idx],
                    phase_index: phase_idx,
                    total_phases: GIT_PHASES.len(),
                    items_completed: items_done,
                    items_total,
                });
            }
        };

        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);
        let start = Instant::now();

        let repo_path = self.repo_path(mount_point, iteration);
        let repo = Repository::open(&repo_path)?;

        // Collect all files in the repo
        let all_files = self.collect_repo_files(&repo_path)?;
        let num_files = all_files.len();

        tracing::debug!("Working with {} files in ripgrep repo", num_files);

        // ===== Phase 1: git status (metadata heavy) =====
        report(0, Some(0), Some(2));
        {
            let statuses = repo.statuses(None)?;
            std::hint::black_box(statuses.len());
            report(0, Some(1), Some(2));

            let statuses = repo.statuses(None)?;
            std::hint::black_box(statuses.len());
            report(0, Some(2), Some(2));
        }

        // ===== Phase 2: Modify working tree =====
        let mut indices: Vec<usize> = (0..num_files).collect();
        indices.shuffle(&mut rng);

        let modify_count = FILES_TO_MODIFY.min(num_files / 3);
        let delete_count = FILES_TO_DELETE.min(num_files / 10);
        let total_modifications = modify_count + FILES_TO_CREATE + delete_count;

        let modify_indices: Vec<usize> = indices[..modify_count].to_vec();
        let delete_indices: Vec<usize> =
            indices[modify_count..modify_count + delete_count].to_vec();

        report(1, Some(0), Some(total_modifications));
        let mut completed = 0;

        // Modify files
        for &idx in &modify_indices {
            let rel_path = &all_files[idx];
            let full_path = repo_path.join(rel_path);

            if full_path.exists() {
                let mut content = fs::read(&full_path)?;
                writeln!(content, "\n// Modified by benchmark at iteration {idx}")
                    .expect("Failed to write to in-memory buffer - system OOM");
                let mut file = File::create(&full_path)?;
                file.write_all(&content)?;
                safe_sync(&file)?;
            }
            completed += 1;
            if completed % 5 == 0 {
                report(1, Some(completed), Some(total_modifications));
            }
        }

        // Create new files
        let gen_dir = repo_path.join("crates").join("bench_generated");
        fs::create_dir_all(&gen_dir)?;

        for i in 0..FILES_TO_CREATE {
            let filename = format!("bench_file_{i:03}.rs");
            let full_path = gen_dir.join(&filename);

            let content = self.generate_new_file(&mut rng, i);
            let mut file = File::create(&full_path)?;
            file.write_all(&content)?;
            safe_sync(&file)?;
            completed += 1;
        }
        report(1, Some(completed), Some(total_modifications));

        // Delete files
        for &idx in &delete_indices {
            let rel_path = &all_files[idx];
            let full_path = repo_path.join(rel_path);
            if full_path.exists() {
                fs::remove_file(&full_path)?;
            }
            completed += 1;
        }
        report(1, Some(completed), Some(total_modifications));

        // ===== Phase 3: git status after changes =====
        report(2, None, None);
        {
            let statuses = repo.statuses(None)?;
            std::hint::black_box(statuses.len());
        }
        report(2, Some(1), Some(1));

        // ===== Phase 4: git add & commit (multiple commits) =====
        report(3, Some(0), Some(NUM_COMMITS));
        for commit_num in 0..NUM_COMMITS {
            let mut index = repo.index()?;

            index.add_all(["*"].iter(), IndexAddOption::DEFAULT, None)?;
            index.update_all(["*"].iter(), None)?;
            index.write()?;

            let tree_id = index.write_tree()?;
            let tree = repo.find_tree(tree_id)?;
            let sig = self.signature()?;

            let head = repo.head()?;
            let parent_commit = head.peel_to_commit()?;

            repo.commit(
                Some("HEAD"),
                &sig,
                &sig,
                &format!("Benchmark commit {commit_num}"),
                &tree,
                &[&parent_commit],
            )?;

            report(3, Some(commit_num + 1), Some(NUM_COMMITS));

            // Make a small change for the next commit
            if commit_num < NUM_COMMITS - 1 && !modify_indices.is_empty() {
                let idx = modify_indices[commit_num % modify_indices.len()];
                let rel_path = &all_files[idx];
                let full_path = repo_path.join(rel_path);

                if full_path.exists() {
                    let mut content = fs::read(&full_path)?;
                    writeln!(content, "// Commit {commit_num} change")
                        .expect("Failed to write to in-memory buffer - system OOM");
                    let mut file = File::create(&full_path)?;
                    file.write_all(&content)?;
                    safe_sync(&file)?;
                }
            }
        }

        // ===== Phase 5: git log (walk commit history) =====
        report(4, Some(0), Some(LOG_ENTRIES_TO_READ));
        {
            let mut revwalk = repo.revwalk()?;
            revwalk.push_head()?;

            for (count, oid) in revwalk.enumerate() {
                if count >= LOG_ENTRIES_TO_READ {
                    break;
                }

                let oid = oid?;
                let commit = repo.find_commit(oid)?;

                std::hint::black_box(commit.message());
                std::hint::black_box(commit.author().name());
                std::hint::black_box(commit.time().seconds());

                let tree = commit.tree()?;
                std::hint::black_box(tree.len());

                report(4, Some(count + 1), Some(LOG_ENTRIES_TO_READ));
            }
        }

        // ===== Phase 6: git diff (compare trees) =====
        report(5, None, None);
        {
            let head = repo.head()?;
            let head_commit = head.peel_to_commit()?;

            if let Ok(parent) = head_commit.parent(0) {
                let parent_tree = parent.tree()?;
                let head_tree = head_commit.tree()?;

                let diff = repo.diff_tree_to_tree(Some(&parent_tree), Some(&head_tree), None)?;
                std::hint::black_box(diff.stats()?.files_changed());
            }
        }
        report(5, Some(1), Some(1));

        Ok(start.elapsed())
    }
}
