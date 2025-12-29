//! Git Workflow Workload
//!
//! Uses real libgit2 to simulate git operations on ripgrep source code:
//! - git init, git add, git commit, git status, git log
//! - Heavy on metadata operations (stat storms), directory traversal, and read-after-write patterns.
//!
//! Downloads ripgrep source (~1MB compressed, expands to realistic Rust project)
//! for testing repository operations on encrypted storage.

use crate::assets::{AssetDownloader, manifest::GIT_RIPGREP};
use crate::bench::Benchmark;
use crate::config::OperationType;
use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use git2::{IndexAddOption, Repository, Signature};
use oxcrypt_mount::safe_sync;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tar::Archive;

// Workload parameters
const FILES_TO_MODIFY: usize = 20;
const FILES_TO_CREATE: usize = 10;
const FILES_TO_DELETE: usize = 5;
const NUM_COMMITS: usize = 5;
const LOG_ENTRIES_TO_READ: usize = 20;

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
    seed: u64,
}

impl GitWorkload {
    /// Create a new git workload.
    pub fn new() -> Self {
        Self { seed: 0x617_C0DE }
    }

    fn workload_dir(&self, mount_point: &Path) -> PathBuf {
        mount_point.join("bench_git_workload")
    }

    fn repo_path(&self, mount_point: &Path) -> PathBuf {
        self.workload_dir(mount_point).join("repo")
    }

    /// Create the signature for commits.
    fn signature(&self) -> Result<Signature<'static>> {
        Ok(Signature::now("Benchmark User", "bench@example.com")?)
    }

    /// Extract ripgrep source tarball to the repo directory.
    fn extract_ripgrep(&self, repo_path: &Path) -> Result<()> {
        let downloader = AssetDownloader::new()?;

        // Ensure the asset is downloaded
        let tarball_path = downloader.ensure(&GIT_RIPGREP)?;

        // Extract tarball
        tracing::debug!("Extracting ripgrep source to {:?}", repo_path);
        let tar_gz = File::open(&tarball_path)
            .with_context(|| format!("Failed to open {:?}", tarball_path))?;
        let tar = GzDecoder::new(tar_gz);
        let mut archive = Archive::new(tar);

        // Disable mtime preservation - FUSE mounts can fail when setting mtime
        // after write due to attribute cache timing or AppleDouble file interference
        archive.set_preserve_mtime(false);

        // Extract to a temp location first
        let temp_extract = repo_path.parent().unwrap().join("ripgrep_temp");
        fs::create_dir_all(&temp_extract)?;
        archive.unpack(&temp_extract)?;

        // Move contents from ripgrep-X.Y.Z/ to repo_path
        // The tarball has a top-level directory like "ripgrep-14.1.0"
        for entry in fs::read_dir(&temp_extract)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                // This should be the ripgrep-X.Y.Z directory
                let src_dir = entry.path();
                // Move all contents to repo_path
                for item in fs::read_dir(&src_dir)? {
                    let item = item?;
                    let dest = repo_path.join(item.file_name());
                    fs::rename(item.path(), dest)?;
                }
                break;
            }
        }

        // Clean up temp directory
        fs::remove_dir_all(&temp_extract)?;

        Ok(())
    }

    /// Collect all file paths in the repository (relative paths).
    fn collect_repo_files(&self, repo_path: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        self.walk_files(repo_path, repo_path, &mut files)?;
        Ok(files)
    }

    fn walk_files(&self, base: &Path, dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            // Skip .git directory
            if path.file_name().map_or(false, |n| n == ".git") {
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

        writeln!(content, "// Benchmark generated file {}", index).unwrap();
        writeln!(content, "// This file was created during the git workload benchmark").unwrap();
        writeln!(content).unwrap();

        while content.len() < size {
            let line: String = (0..60)
                .map(|_| (b'a' + (rng.random::<u8>() % 26)) as char)
                .collect();
            writeln!(content, "// {}", line).unwrap();
        }

        content.truncate(size);
        content
    }
}

impl Default for GitWorkload {
    fn default() -> Self {
        Self::new()
    }
}

impl Benchmark for GitWorkload {
    fn name(&self) -> &str {
        "Git Workflow (ripgrep)"
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

    fn setup(&self, mount_point: &Path) -> Result<()> {
        // Create workload directory
        let repo_path = self.repo_path(mount_point);
        fs::create_dir_all(&repo_path)?;

        // Extract ripgrep source
        tracing::info!("Setting up git workload with ripgrep source...");
        self.extract_ripgrep(&repo_path)?;

        // Initialize git repository
        let repo = Repository::init(&repo_path)?;

        // Stage all files
        let mut index = repo.index()?;
        index.add_all(["*"].iter(), IndexAddOption::DEFAULT, None)?;
        index.write()?;

        // Create initial commit
        let tree_id = index.write_tree()?;
        let tree = repo.find_tree(tree_id)?;
        let sig = self.signature()?;

        repo.commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[])?;

        tracing::info!("Git workload setup complete");
        Ok(())
    }

    fn run(&self, mount_point: &Path) -> Result<Duration> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);
        let start = Instant::now();

        let repo_path = self.repo_path(mount_point);
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
                writeln!(content, "\n// Modified by benchmark at iteration {}", idx).unwrap();
                let mut file = File::create(&full_path)?;
                file.write_all(&content)?;
                safe_sync(&file)?;
            }
        }

        // Create new files in a bench_generated directory
        let gen_dir = repo_path.join("crates").join("bench_generated");
        fs::create_dir_all(&gen_dir)?;

        for i in 0..FILES_TO_CREATE {
            let filename = format!("bench_file_{:03}.rs", i);
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
                &format!("Benchmark commit {}", commit_num),
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
                    writeln!(content, "// Commit {} change", commit_num).unwrap();
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

    fn cleanup(&self, mount_point: &Path) -> Result<()> {
        let workload_dir = self.workload_dir(mount_point);
        if workload_dir.exists() {
            fs::remove_dir_all(&workload_dir)?;
        }
        Ok(())
    }

    fn warmup_iterations(&self) -> usize {
        1
    }
}
