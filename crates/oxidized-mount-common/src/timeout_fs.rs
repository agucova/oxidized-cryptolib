//! Timeout-protected filesystem operations.
//!
//! This module provides filesystem operations that won't block indefinitely
//! on stale FUSE mounts or other unresponsive filesystems.
//!
//! # Problem
//!
//! Standard library filesystem operations (`std::fs::*`) can block indefinitely
//! when operating on paths that are on stale/crashed FUSE mounts. The kernel
//! waits for the FUSE daemon to respond, but if it's dead, the call never returns.
//!
//! # Solution
//!
//! Each operation spawns a thread and uses `mpsc::channel` with `recv_timeout`
//! to enforce a deadline. If the operation doesn't complete in time, we return
//! a timeout error.
//!
//! # Example
//!
//! ```
//! use oxidized_mount_common::TimeoutFs;
//! use std::time::Duration;
//!
//! let fs = TimeoutFs::new(Duration::from_secs(5));
//!
//! match fs.read_to_string("/path/to/file") {
//!     Ok(content) => println!("Read {} bytes", content.len()),
//!     Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
//!         println!("Operation timed out - path may be on stale mount");
//!     }
//!     Err(e) => println!("Other error: {}", e),
//! }
//! ```

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

/// Default timeout for filesystem operations.
pub const DEFAULT_FS_TIMEOUT: Duration = Duration::from_secs(5);

/// Filesystem operations with timeout protection.
///
/// Each method spawns a thread to perform the operation, allowing us to
/// enforce a timeout even when the underlying syscall blocks.
#[derive(Debug, Clone)]
pub struct TimeoutFs {
    timeout: Duration,
}

impl Default for TimeoutFs {
    fn default() -> Self {
        Self::new(DEFAULT_FS_TIMEOUT)
    }
}

impl TimeoutFs {
    /// Create a new TimeoutFs with the specified timeout.
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Create a TimeoutFs with the default timeout (5 seconds).
    pub fn with_default_timeout() -> Self {
        Self::default()
    }

    /// Get the configured timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Run an operation with timeout, returning a timeout error if it doesn't complete.
    fn run_with_timeout<T, F>(&self, op: F) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> io::Result<T> + Send + 'static,
    {
        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            let result = op();
            let _ = tx.send(result);
        });

        match rx.recv_timeout(self.timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Filesystem operation timed out - path may be on a stale mount",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::other(
                "Filesystem operation thread terminated unexpectedly",
            )),
        }
    }

    /// Read the entire contents of a file into a string.
    ///
    /// Equivalent to `std::fs::read_to_string` but with timeout protection.
    pub fn read_to_string(&self, path: impl AsRef<Path>) -> io::Result<String> {
        let path = path.as_ref().to_path_buf();
        self.run_with_timeout(move || fs::read_to_string(&path))
    }

    /// Read the entire contents of a file into a byte vector.
    ///
    /// Equivalent to `std::fs::read` but with timeout protection.
    pub fn read(&self, path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
        let path = path.as_ref().to_path_buf();
        self.run_with_timeout(move || fs::read(&path))
    }

    /// Write a slice as the entire contents of a file.
    ///
    /// Equivalent to `std::fs::write` but with timeout protection.
    pub fn write(&self, path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
        let path = path.as_ref().to_path_buf();
        let contents = contents.as_ref().to_vec();
        self.run_with_timeout(move || fs::write(&path, contents))
    }

    /// Get metadata for a path.
    ///
    /// Equivalent to `std::fs::metadata` but with timeout protection.
    pub fn metadata(&self, path: impl AsRef<Path>) -> io::Result<Metadata> {
        let path = path.as_ref().to_path_buf();
        self.run_with_timeout(move || fs::metadata(&path))
    }

    /// Check if a path exists.
    ///
    /// Unlike `Path::exists()`, this version has timeout protection.
    pub fn exists(&self, path: impl AsRef<Path>) -> bool {
        self.metadata(path).is_ok()
    }

    /// Check if a path is a directory.
    ///
    /// Unlike `Path::is_dir()`, this version has timeout protection.
    pub fn is_dir(&self, path: impl AsRef<Path>) -> bool {
        self.metadata(path).map(|m| m.is_dir()).unwrap_or(false)
    }

    /// Check if a path is a file.
    ///
    /// Unlike `Path::is_file()`, this version has timeout protection.
    pub fn is_file(&self, path: impl AsRef<Path>) -> bool {
        self.metadata(path).map(|m| m.is_file()).unwrap_or(false)
    }

    /// Create a directory and all of its parent components.
    ///
    /// Equivalent to `std::fs::create_dir_all` but with timeout protection.
    pub fn create_dir_all(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref().to_path_buf();
        self.run_with_timeout(move || fs::create_dir_all(&path))
    }

    /// Create a directory.
    ///
    /// Equivalent to `std::fs::create_dir` but with timeout protection.
    pub fn create_dir(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref().to_path_buf();
        self.run_with_timeout(move || fs::create_dir(&path))
    }

    /// Remove a file.
    ///
    /// Equivalent to `std::fs::remove_file` but with timeout protection.
    pub fn remove_file(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref().to_path_buf();
        self.run_with_timeout(move || fs::remove_file(&path))
    }

    /// Remove a directory (must be empty).
    ///
    /// Equivalent to `std::fs::remove_dir` but with timeout protection.
    pub fn remove_dir(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref().to_path_buf();
        self.run_with_timeout(move || fs::remove_dir(&path))
    }

    /// Remove a directory and all its contents.
    ///
    /// Equivalent to `std::fs::remove_dir_all` but with timeout protection.
    pub fn remove_dir_all(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref().to_path_buf();
        self.run_with_timeout(move || fs::remove_dir_all(&path))
    }

    /// Rename a file or directory.
    ///
    /// Equivalent to `std::fs::rename` but with timeout protection.
    pub fn rename(&self, from: impl AsRef<Path>, to: impl AsRef<Path>) -> io::Result<()> {
        let from = from.as_ref().to_path_buf();
        let to = to.as_ref().to_path_buf();
        self.run_with_timeout(move || fs::rename(&from, &to))
    }

    /// Copy a file.
    ///
    /// Equivalent to `std::fs::copy` but with timeout protection.
    pub fn copy(&self, from: impl AsRef<Path>, to: impl AsRef<Path>) -> io::Result<u64> {
        let from = from.as_ref().to_path_buf();
        let to = to.as_ref().to_path_buf();
        self.run_with_timeout(move || fs::copy(&from, &to))
    }

    /// Read a directory's contents.
    ///
    /// Returns a vector of directory entries. Note that this reads all entries
    /// into memory, unlike the iterator returned by `std::fs::read_dir`.
    pub fn read_dir(&self, path: impl AsRef<Path>) -> io::Result<Vec<fs::DirEntry>> {
        let path = path.as_ref().to_path_buf();
        self.run_with_timeout(move || {
            fs::read_dir(&path)?
                .collect::<Result<Vec<_>, _>>()
        })
    }

    /// Canonicalize a path (resolve symlinks and make absolute).
    ///
    /// Equivalent to `std::fs::canonicalize` but with timeout protection.
    pub fn canonicalize(&self, path: impl AsRef<Path>) -> io::Result<PathBuf> {
        let path = path.as_ref().to_path_buf();
        self.run_with_timeout(move || fs::canonicalize(&path))
    }

    /// Open a file with custom options and read its contents.
    ///
    /// This is useful when you need specific open options but still want
    /// timeout protection on the read.
    pub fn open_and_read(&self, path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
        let path = path.as_ref().to_path_buf();
        self.run_with_timeout(move || {
            let mut file = File::open(&path)?;
            let mut contents = Vec::new();
            file.read_to_end(&mut contents)?;
            Ok(contents)
        })
    }

    /// Create/truncate a file and write contents.
    ///
    /// This is useful when you need specific open options but still want
    /// timeout protection on the write.
    pub fn create_and_write(&self, path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
        let path = path.as_ref().to_path_buf();
        let contents = contents.as_ref().to_vec();
        self.run_with_timeout(move || {
            let mut file = File::create(&path)?;
            file.write_all(&contents)?;
            file.sync_all()?;
            Ok(())
        })
    }

    /// Open a file with custom options.
    ///
    /// Note: The returned `File` handle is NOT timeout-protected for subsequent
    /// read/write operations. Use `open_and_read` or `create_and_write` for
    /// fully protected operations.
    pub fn open_with_options(&self, path: impl AsRef<Path>, options: &OpenOptions) -> io::Result<File> {
        let path = path.as_ref().to_path_buf();
        let options = options.clone();
        self.run_with_timeout(move || options.open(&path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_read_write_string() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("test.txt");
        let fs = TimeoutFs::default();

        // Write
        fs.write(&path, "hello world").unwrap();

        // Read
        let content = fs.read_to_string(&path).unwrap();
        assert_eq!(content, "hello world");
    }

    #[test]
    fn test_exists() {
        let temp = TempDir::new().unwrap();
        let fs = TimeoutFs::default();

        assert!(fs.exists(temp.path()));
        assert!(!fs.exists(temp.path().join("nonexistent")));
    }

    #[test]
    fn test_is_dir() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("file.txt");
        std::fs::write(&file_path, "test").unwrap();

        let fs = TimeoutFs::default();
        assert!(fs.is_dir(temp.path()));
        assert!(!fs.is_dir(&file_path));
    }

    #[test]
    fn test_create_dir_all() {
        let temp = TempDir::new().unwrap();
        let deep_path = temp.path().join("a").join("b").join("c");
        let fs = TimeoutFs::default();

        fs.create_dir_all(&deep_path).unwrap();
        assert!(deep_path.exists());
    }

    #[test]
    fn test_metadata() {
        let temp = TempDir::new().unwrap();
        let fs = TimeoutFs::default();

        let meta = fs.metadata(temp.path()).unwrap();
        assert!(meta.is_dir());
    }

    #[test]
    fn test_read_dir() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join("a.txt"), "a").unwrap();
        std::fs::write(temp.path().join("b.txt"), "b").unwrap();

        let fs = TimeoutFs::default();
        let entries = fs.read_dir(temp.path()).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_nonexistent_path_error() {
        let fs = TimeoutFs::default();
        let result = fs.read_to_string("/nonexistent/path/12345");
        assert!(result.is_err());
    }

    #[test]
    fn test_custom_timeout() {
        let fs = TimeoutFs::new(Duration::from_millis(100));
        assert_eq!(fs.timeout(), Duration::from_millis(100));
    }
}
