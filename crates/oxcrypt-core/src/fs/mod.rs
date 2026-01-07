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
pub use file::{
    DecryptedFile, FileHeader, decrypt_dir_id_backup, decrypt_file, decrypt_file_content,
    decrypt_file_header, encrypt_dir_id_backup, encrypt_file_content, encrypt_file_header,
};
pub use name::{
    decrypt_filename, decrypt_parent_dir_id, encrypt_filename, encrypt_parent_dir_id, hash_dir_id,
};
pub use symlink::{SymlinkError, decrypt_symlink_target, encrypt_symlink_target};

#[cfg(feature = "async")]
pub use file_async::{decrypt_file_async, decrypt_file_with_context_async};

#[cfg(feature = "async")]
pub use streaming::{
    CHUNK_ENCRYPTED_SIZE, CHUNK_OVERHEAD, CHUNK_PLAINTEXT_SIZE, HEADER_SIZE, StreamingContext,
    StreamingError, VaultFileReader, VaultFileWriter, chunk_to_encrypted_offset,
    encrypted_to_plaintext_size, encrypted_to_plaintext_size_or_zero, plaintext_to_chunk_number,
    plaintext_to_chunk_offset,
};
