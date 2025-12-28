//! Filesystem abstractions for Cryptomator vaults

pub mod directory;
pub mod file;
pub mod file_ctrmac;
pub mod name;
pub mod symlink;

#[cfg(feature = "async")]
pub mod file_async;

#[cfg(feature = "async")]
pub mod streaming;

// Re-export commonly used types
pub use directory::{DirectoryEntry, EntryKind, VaultExplorer, print_tree};
pub use file::{decrypt_file, encrypt_file_header, encrypt_file_content, decrypt_file_header, decrypt_file_content, DecryptedFile, FileHeader, encrypt_dir_id_backup, decrypt_dir_id_backup};
pub use name::{encrypt_filename, decrypt_filename, hash_dir_id, encrypt_parent_dir_id, decrypt_parent_dir_id};
pub use symlink::{encrypt_symlink_target, decrypt_symlink_target, SymlinkError};

#[cfg(feature = "async")]
pub use file_async::{decrypt_file_async, decrypt_file_with_context_async};

#[cfg(feature = "async")]
pub use streaming::{
    VaultFileReader, VaultFileWriter, StreamingError, StreamingContext,
    HEADER_SIZE, CHUNK_PLAINTEXT_SIZE, CHUNK_ENCRYPTED_SIZE, CHUNK_OVERHEAD,
    plaintext_to_chunk_number, plaintext_to_chunk_offset, chunk_to_encrypted_offset,
    encrypted_to_plaintext_size, encrypted_to_plaintext_size_or_zero,
};