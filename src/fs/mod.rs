//! Filesystem abstractions for Cryptomator vaults

pub mod directory;
pub mod file;
pub mod name;
pub mod symlink;

// Re-export commonly used types
pub use directory::{DirectoryEntry, EntryKind, VaultExplorer, print_tree};
pub use file::{decrypt_file, encrypt_file_header, encrypt_file_content, decrypt_file_header, decrypt_file_content, DecryptedFile, FileHeader};
pub use name::{encrypt_filename, decrypt_filename, hash_dir_id, encrypt_parent_dir_id, decrypt_parent_dir_id};
pub use symlink::{encrypt_symlink_target, decrypt_symlink_target, SymlinkError};