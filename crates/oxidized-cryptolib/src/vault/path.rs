//! Type-safe path handling for Cryptomator vaults.
//!
//! This module provides two distinct types to prevent confusion between:
//! - `DirId`: Internal directory identifiers (opaque UUIDs)
//! - `VaultPath`: User-facing paths within the vault (e.g., "/Documents/file.txt")

use relative_path::{RelativePath, RelativePathBuf};
use std::fmt;

/// Opaque directory identifier used internally by Cryptomator.
///
/// Directory IDs are UUIDs stored in `dir.c9r` files. They are used as
/// associated data for filename encryption, binding filenames to their
/// parent directory.
///
/// # Examples
///
/// ```
/// use oxidized_cryptolib::vault::path::DirId;
///
/// // Root directory
/// let root = DirId::root();
/// assert!(root.is_root());
///
/// // Directory ID from a dir.c9r file
/// let dir_id = DirId::from_raw("550e8400-e29b-41d4-a716-446655440000");
/// assert!(!dir_id.is_root());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DirId(String);

impl DirId {
    /// The root directory (empty string ID).
    #[inline]
    pub fn root() -> Self {
        DirId(String::new())
    }

    /// Create a DirId from a raw string (e.g., from a dir.c9r file).
    ///
    /// This should only be used when reading directory IDs from the vault
    /// structure, not for user-provided paths.
    #[inline]
    pub fn from_raw(id: impl Into<String>) -> Self {
        DirId(id.into())
    }

    /// Check if this is the root directory.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// Get the raw string representation.
    ///
    /// This is mainly useful for internal operations like hashing.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for DirId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DirId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            write!(f, "<root>")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

/// User-facing path within a Cryptomator vault.
///
/// Vault paths use `/` as the separator regardless of the host OS.
/// They represent the logical structure the user sees, not the encrypted
/// on-disk layout.
///
/// # Examples
///
/// ```
/// use oxidized_cryptolib::vault::path::VaultPath;
///
/// let path = VaultPath::new("/Documents/report.txt");
/// assert_eq!(path.file_name(), Some("report.txt"));
/// assert_eq!(path.parent().unwrap().as_str(), "Documents");
///
/// // Paths are normalized (leading slash removed)
/// let path2 = VaultPath::new("Documents/report.txt");
/// assert_eq!(path, path2);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VaultPath(RelativePathBuf);

impl VaultPath {
    /// The root path (empty).
    #[inline]
    pub fn root() -> Self {
        VaultPath(RelativePathBuf::new())
    }

    /// Create a new vault path from a string.
    ///
    /// Leading slashes are stripped, and the path is normalized.
    pub fn new(path: impl AsRef<str>) -> Self {
        let s = path.as_ref().trim_start_matches('/');
        VaultPath(RelativePathBuf::from(s))
    }

    /// Check if this is the root path.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.0.as_str().is_empty()
    }

    /// Get the string representation of this path.
    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Get the underlying `RelativePath`.
    #[inline]
    pub fn as_relative_path(&self) -> &RelativePath {
        &self.0
    }

    /// Join this path with another component.
    ///
    /// # Examples
    ///
    /// ```
    /// use oxidized_cryptolib::vault::path::VaultPath;
    ///
    /// let docs = VaultPath::new("Documents");
    /// let file = docs.join("report.txt");
    /// assert_eq!(file.as_str(), "Documents/report.txt");
    /// ```
    pub fn join(&self, component: impl AsRef<str>) -> Self {
        VaultPath(self.0.join(component.as_ref()))
    }

    /// Get the parent path, if any.
    ///
    /// Returns `None` for the root path.
    pub fn parent(&self) -> Option<VaultPath> {
        self.0.parent().map(|p| VaultPath(p.to_relative_path_buf()))
    }

    /// Get the final component of this path (filename or directory name).
    ///
    /// Returns `None` for the root path.
    pub fn file_name(&self) -> Option<&str> {
        self.0.file_name()
    }

    /// Iterate over the components of this path.
    ///
    /// # Examples
    ///
    /// ```
    /// use oxidized_cryptolib::vault::path::VaultPath;
    ///
    /// let path = VaultPath::new("Documents/Photos/vacation.jpg");
    /// let components: Vec<_> = path.components().collect();
    /// assert_eq!(components, vec!["Documents", "Photos", "vacation.jpg"]);
    /// ```
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.components().map(|c| c.as_str())
    }

    /// Split this path into parent directory path and filename.
    ///
    /// Returns `None` for the root path.
    ///
    /// # Examples
    ///
    /// ```
    /// use oxidized_cryptolib::vault::path::VaultPath;
    ///
    /// let path = VaultPath::new("Documents/report.txt");
    /// let (parent, name) = path.split().unwrap();
    /// assert_eq!(parent.as_str(), "Documents");
    /// assert_eq!(name, "report.txt");
    /// ```
    pub fn split(&self) -> Option<(VaultPath, &str)> {
        let parent = self.parent()?;
        let name = self.file_name()?;
        Some((parent, name))
    }
}

impl AsRef<str> for VaultPath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<RelativePath> for VaultPath {
    fn as_ref(&self) -> &RelativePath {
        &self.0
    }
}

impl fmt::Display for VaultPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            write!(f, "/")
        } else {
            write!(f, "/{}", self.0)
        }
    }
}

impl From<&str> for VaultPath {
    fn from(s: &str) -> Self {
        VaultPath::new(s)
    }
}

impl From<String> for VaultPath {
    fn from(s: String) -> Self {
        VaultPath::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dir_id_root() {
        let root = DirId::root();
        assert!(root.is_root());
        assert_eq!(root.as_str(), "");
        assert_eq!(root.to_string(), "<root>");
    }

    #[test]
    fn test_dir_id_from_raw() {
        let id = DirId::from_raw("abc-123-def");
        assert!(!id.is_root());
        assert_eq!(id.as_str(), "abc-123-def");
        assert_eq!(id.to_string(), "abc-123-def");
    }

    #[test]
    fn test_dir_id_equality() {
        let id1 = DirId::from_raw("abc");
        let id2 = DirId::from_raw("abc");
        let id3 = DirId::from_raw("def");

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_vault_path_root() {
        let root = VaultPath::root();
        assert!(root.is_root());
        assert_eq!(root.as_str(), "");
        assert_eq!(root.to_string(), "/");
    }

    #[test]
    fn test_vault_path_normalization() {
        // Leading slashes are stripped
        let p1 = VaultPath::new("/Documents/file.txt");
        let p2 = VaultPath::new("Documents/file.txt");
        assert_eq!(p1, p2);
        assert_eq!(p1.as_str(), "Documents/file.txt");
    }

    #[test]
    fn test_vault_path_join() {
        let docs = VaultPath::new("Documents");
        let file = docs.join("report.txt");
        assert_eq!(file.as_str(), "Documents/report.txt");

        let root = VaultPath::root();
        let top = root.join("file.txt");
        assert_eq!(top.as_str(), "file.txt");
    }

    #[test]
    fn test_vault_path_parent() {
        let path = VaultPath::new("Documents/Photos/vacation.jpg");

        let parent1 = path.parent().unwrap();
        assert_eq!(parent1.as_str(), "Documents/Photos");

        let parent2 = parent1.parent().unwrap();
        assert_eq!(parent2.as_str(), "Documents");

        let parent3 = parent2.parent().unwrap();
        assert!(parent3.is_root());

        assert!(parent3.parent().is_none());
    }

    #[test]
    fn test_vault_path_file_name() {
        let path = VaultPath::new("Documents/report.txt");
        assert_eq!(path.file_name(), Some("report.txt"));

        let dir = VaultPath::new("Documents");
        assert_eq!(dir.file_name(), Some("Documents"));

        let root = VaultPath::root();
        assert_eq!(root.file_name(), None);
    }

    #[test]
    fn test_vault_path_components() {
        let path = VaultPath::new("Documents/Photos/vacation.jpg");
        let components: Vec<_> = path.components().collect();
        assert_eq!(components, vec!["Documents", "Photos", "vacation.jpg"]);

        let root = VaultPath::root();
        let components: Vec<_> = root.components().collect();
        assert!(components.is_empty());
    }

    #[test]
    fn test_vault_path_split() {
        let path = VaultPath::new("Documents/report.txt");
        let (parent, name) = path.split().unwrap();
        assert_eq!(parent.as_str(), "Documents");
        assert_eq!(name, "report.txt");

        let top_level = VaultPath::new("file.txt");
        let (parent, name) = top_level.split().unwrap();
        assert!(parent.is_root());
        assert_eq!(name, "file.txt");

        let root = VaultPath::root();
        assert!(root.split().is_none());
    }

    #[test]
    fn test_vault_path_display() {
        let root = VaultPath::root();
        assert_eq!(format!("{}", root), "/");

        let path = VaultPath::new("Documents/file.txt");
        assert_eq!(format!("{}", path), "/Documents/file.txt");
    }

    #[test]
    fn test_vault_path_from_conversions() {
        let p1: VaultPath = "Documents/file.txt".into();
        let p2: VaultPath = String::from("Documents/file.txt").into();
        assert_eq!(p1, p2);
    }
}
