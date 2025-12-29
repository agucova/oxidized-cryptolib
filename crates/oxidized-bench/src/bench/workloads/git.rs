//! Git Workflow Workload
//!
//! Uses real libgit2 to simulate git operations:
//! - git init, git add, git commit, git status, git log
//! - Heavy on metadata operations (stat storms), directory traversal, and read-after-write patterns.
//!
//! Tests repository operations on encrypted storage.

use crate::bench::Benchmark;
use crate::config::OperationType;
use anyhow::Result;
use git2::{IndexAddOption, Repository, Signature};
use oxidized_mount_common::safe_sync;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const NUM_FILES: usize = 100;
const DIRECTORY_DEPTH: usize = 3;
const FILES_TO_MODIFY: usize = 10;
const FILES_TO_CREATE: usize = 5;
const FILES_TO_DELETE: usize = 3;
const NUM_COMMITS: usize = 5;
const LOG_ENTRIES_TO_READ: usize = 20;

/// Git Workflow Workload using real libgit2.
///
/// Phases:
/// 1. git init - Initialize a real git repository
/// 2. Initial commit - Add all files and commit
/// 3. git status - Check working tree status (metadata heavy)
/// 4. Modify working tree - Modify, create, and delete files
/// 5. git add & commit - Stage changes and create commits
/// 6. git log - Walk commit history
pub struct GitWorkload {
    seed: u64,
}

impl GitWorkload {
    pub fn new() -> Self {
        Self { seed: 0x617_C0DE }
    }

    fn workload_dir(&self, mount_point: &Path) -> PathBuf {
        mount_point.join("bench_git_workload")
    }

    fn repo_path(&self, mount_point: &Path) -> PathBuf {
        self.workload_dir(mount_point).join("repo")
    }

    /// Generate nested directory structure path for a file.
    fn nested_path(&self, index: usize) -> PathBuf {
        let mut path = PathBuf::new();

        // Create nested structure based on index
        for depth in 0..DIRECTORY_DEPTH {
            let dir_num = (index / (10_usize.pow((DIRECTORY_DEPTH - depth - 1) as u32))) % 10;
            path = path.join(format!("dir_{}", dir_num));
        }

        path.join(format!("file_{:04}.txt", index))
    }

    /// Generate a deterministic content for source files.
    fn generate_file_content(&self, rng: &mut ChaCha8Rng, index: usize) -> Vec<u8> {
        let size = 1024 + rng.random_range(0..9 * 1024); // 1KB-10KB
        let mut content = Vec::with_capacity(size);

        writeln!(content, "// Source file {}", index).unwrap();
        writeln!(content, "// Tracking: enabled").unwrap();
        writeln!(content).unwrap();

        while content.len() < size {
            let line: String = (0..60)
                .map(|_| (b'a' + (rng.random::<u8>() % 26)) as char)
                .collect();
            writeln!(content, "{}", line).unwrap();
        }

        content.truncate(size);
        content
    }

    /// Create the signature for commits.
    fn signature(&self) -> Result<Signature<'static>> {
        Ok(Signature::now("Benchmark User", "bench@example.com")?)
    }
}

impl Default for GitWorkload {
    fn default() -> Self {
        Self::new()
    }
}

impl Benchmark for GitWorkload {
    fn name(&self) -> &str {
        "Git Workflow"
    }

    fn operation(&self) -> OperationType {
        OperationType::GitWorkload
    }

    fn parameters(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        params.insert("files".to_string(), NUM_FILES.to_string());
        params.insert("depth".to_string(), DIRECTORY_DEPTH.to_string());
        params.insert("modify".to_string(), FILES_TO_MODIFY.to_string());
        params.insert("create".to_string(), FILES_TO_CREATE.to_string());
        params.insert("delete".to_string(), FILES_TO_DELETE.to_string());
        params.insert("commits".to_string(), NUM_COMMITS.to_string());
        params
    }

    fn setup(&self, mount_point: &Path) -> Result<()> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed);

        // Create workload directory
        let repo_path = self.repo_path(mount_point);
        fs::create_dir_all(&repo_path)?;

        // Initialize git repository
        let repo = Repository::init(&repo_path)?;

        // Create nested directories and files
        for i in 0..NUM_FILES {
            let rel_path = self.nested_path(i);
            let full_path = repo_path.join(&rel_path);

            if let Some(parent) = full_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let content = self.generate_file_content(&mut rng, i);
            let mut file = File::create(&full_path)?;
            file.write_all(&content)?;
            safe_sync(&file)?;
        }

        // Stage all files
        let mut index = repo.index()?;
        index.add_all(["*"].iter(), IndexAddOption::DEFAULT, None)?;
        index.write()?;

        // Create initial commit
        let tree_id = index.write_tree()?;
        let tree = repo.find_tree(tree_id)?;
        let sig = self.signature()?;

        repo.commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[])?;

        Ok(())
    }

    fn run(&self, mount_point: &Path) -> Result<Duration> {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed + 1);
        let start = Instant::now();

        let repo_path = self.repo_path(mount_point);
        let repo = Repository::open(&repo_path)?;

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
        let mut indices: Vec<usize> = (0..NUM_FILES).collect();
        indices.shuffle(&mut rng);

        let modify_indices: Vec<usize> = indices[..FILES_TO_MODIFY].to_vec();
        let delete_indices: Vec<usize> =
            indices[FILES_TO_MODIFY..FILES_TO_MODIFY + FILES_TO_DELETE].to_vec();

        // Modify files
        for &idx in &modify_indices {
            let rel_path = self.nested_path(idx);
            let full_path = repo_path.join(&rel_path);

            let mut content = fs::read(&full_path)?;
            writeln!(content, "\n// Modified at iteration {}", idx).unwrap();
            let mut file = File::create(&full_path)?;
            file.write_all(&content)?;
            safe_sync(&file)?;
        }

        // Create new files
        let new_file_start = NUM_FILES;
        for i in 0..FILES_TO_CREATE {
            let new_idx = new_file_start + i;
            let rel_path = self.nested_path(new_idx);
            let full_path = repo_path.join(&rel_path);

            if let Some(parent) = full_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let content = self.generate_file_content(&mut rng, new_idx);
            let mut file = File::create(&full_path)?;
            file.write_all(&content)?;
            safe_sync(&file)?;
        }

        // Delete files
        for &idx in &delete_indices {
            let rel_path = self.nested_path(idx);
            let full_path = repo_path.join(&rel_path);
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
            if commit_num < NUM_COMMITS - 1 {
                let idx = modify_indices[commit_num % modify_indices.len()];
                let rel_path = self.nested_path(idx);
                let full_path = repo_path.join(&rel_path);

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
