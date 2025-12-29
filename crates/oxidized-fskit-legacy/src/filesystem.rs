//! FSKit filesystem implementation for Cryptomator vaults.
//!
//! This module implements the `fskit_rs::Filesystem` trait for mounting
//! Cryptomator vaults on macOS 15.4+ using the FSKit framework.

use async_trait::async_trait;
use fskit_rs::{
    directory_entries, AccessMask, CaseFormat, DirectoryEntries, Error as FsKitError, Filesystem,
    Item, ItemAttributes, ItemType, OpenMode, PathConfOperations, PreallocateFlag,
    ResourceIdentifier, Result as FsKitResult, SetXattrPolicy, StatFsResult, SupportedCapabilities,
    SyncFlags, TaskOptions, VolumeBehavior, VolumeIdentifier, Xattrs,
};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, trace};
use uuid::Uuid;

use oxidized_cryptolib::fs::encrypted_to_plaintext_size_or_zero;
use oxidized_cryptolib::fs::streaming::VaultFileReader;
use oxidized_cryptolib::vault::VaultOperationsAsync;
use oxidized_mount_common::{HandleTable, VaultStats, WriteBuffer};

use crate::attr::AttrCache;
use crate::error::{operation_error_to_errno, write_error_to_errno};
use crate::item_table::{ItemKind, ItemTable, ROOT_ITEM_ID};

/// Handle type for FSKit file operations.
///
/// FSKit operations use item IDs directly, so we track open files by their item ID.
#[derive(Debug)]
pub enum FsKitHandle {
    /// Read-only handle using streaming reader.
    ///
    /// Boxed to reduce enum size difference between variants.
    Reader(Box<VaultFileReader>),

    /// Write handle with in-memory buffer.
    ///
    /// Uses read-modify-write pattern for random access writes.
    WriteBuffer(WriteBuffer),
}

impl FsKitHandle {
    /// Check if this is a reader handle.
    #[allow(dead_code)]
    pub fn is_reader(&self) -> bool {
        matches!(self, FsKitHandle::Reader(_))
    }

    /// Check if this is a write buffer handle.
    #[allow(dead_code)]
    pub fn is_write_buffer(&self) -> bool {
        matches!(self, FsKitHandle::WriteBuffer(_))
    }

    /// Get a mutable reference to the write buffer, if this is one.
    pub fn as_write_buffer_mut(&mut self) -> Option<&mut WriteBuffer> {
        match self {
            FsKitHandle::WriteBuffer(b) => Some(b),
            FsKitHandle::Reader(_) => None,
        }
    }
}

/// Type alias for FSKit handle table.
pub type FsKitHandleTable = HandleTable<u64, FsKitHandle>;

/// Block size for filesystem statistics.
const BLOCK_SIZE: u64 = 4096;

/// Default file permissions (rw-r--r--).
const DEFAULT_FILE_PERM: u16 = 0o644;

/// Default directory permissions (rwxr-xr-x).
const DEFAULT_DIR_PERM: u16 = 0o755;

/// FSKit filesystem for Cryptomator vaults.
///
/// Implements the `fskit_rs::Filesystem` trait to provide a mountable filesystem
/// backed by an encrypted Cryptomator vault.
#[derive(Clone)]
pub struct CryptomatorFSKit {
    /// Async vault operations (thread-safe with internal locking).
    ops: Arc<VaultOperationsAsync>,
    /// Item table for path/item_id mapping (DashMap is already Send+Sync).
    items: Arc<ItemTable>,
    /// File handle table for open files (DashMap is already Send+Sync).
    handles: Arc<FsKitHandleTable>,
    /// Attribute cache to reduce vault operations.
    attr_cache: Arc<AttrCache>,
    /// Statistics for monitoring vault activity.
    stats: Arc<VaultStats>,
    /// User ID to use for file ownership.
    uid: u32,
    /// Group ID to use for file ownership.
    gid: u32,
    /// Path to the vault root (for statfs).
    vault_path: PathBuf,
    /// Volume identifier (generated on creation).
    volume_id: String,
}

impl CryptomatorFSKit {
    /// Creates a new CryptomatorFSKit from a vault path and password.
    ///
    /// # Arguments
    ///
    /// * `vault_path` - Path to the Cryptomator vault root directory
    /// * `password` - The vault password
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The vault configuration cannot be read
    /// - The master key cannot be extracted (wrong password)
    /// - The async vault operations cannot be initialized
    pub fn new(vault_path: &Path, password: &str) -> anyhow::Result<Self> {
        // Open vault - extracts key, reads config, configures cipher combo automatically
        let ops = VaultOperationsAsync::open(vault_path, password)
            .map_err(|e| anyhow::anyhow!("Failed to open vault: {e}"))?
            .into_shared();

        // Get current user/group
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        // Generate a unique volume ID
        let volume_id = Uuid::new_v4().to_string();

        // Create stats and connect to attr cache for hit/miss tracking
        let stats = Arc::new(VaultStats::new());
        let mut attr_cache = AttrCache::with_defaults();
        attr_cache.set_stats(stats.cache_stats());

        tracing::info!(
            vault_path = %vault_path.display(),
            uid = uid,
            gid = gid,
            "CryptomatorFSKit initialized"
        );

        Ok(Self {
            ops,
            items: Arc::new(ItemTable::new()),
            handles: Arc::new(FsKitHandleTable::new()),
            attr_cache: Arc::new(attr_cache),
            stats,
            uid,
            gid,
            vault_path: vault_path.to_path_buf(),
            volume_id,
        })
    }

    /// Get the stats for this filesystem.
    pub fn stats(&self) -> Arc<VaultStats> {
        Arc::clone(&self.stats)
    }

    /// Creates ItemAttributes for a directory.
    fn make_dir_attrs(&self, item_id: u64) -> ItemAttributes {
        self.make_dir_attrs_with_parent(item_id, None)
    }

    /// Creates ItemAttributes for a directory with parent_id.
    fn make_dir_attrs_with_parent(&self, item_id: u64, parent_id: Option<u64>) -> ItemAttributes {
        let now = std::time::SystemTime::now();
        let timestamp = prost_types::Timestamp::from(now);
        ItemAttributes {
            file_id: Some(item_id),
            parent_id,
            uid: Some(self.uid),
            gid: Some(self.gid),
            mode: Some(DEFAULT_DIR_PERM as u32 | libc::S_IFDIR as u32),
            r#type: Some(ItemType::Directory.into()),
            link_count: Some(2),
            size: Some(0),
            alloc_size: Some(0),
            access_time: Some(timestamp),
            modify_time: Some(timestamp),
            change_time: Some(timestamp),
            birth_time: Some(timestamp),
            added_time: Some(timestamp),
            backup_time: None,
            flags: Some(0),
            supports_limited_xattrs: Some(false),
            inhibit_kernel_offloaded_io: Some(false),
        }
    }

    /// Creates ItemAttributes for a regular file.
    fn make_file_attrs(&self, item_id: u64, size: u64) -> ItemAttributes {
        self.make_file_attrs_with_parent(item_id, size, None)
    }

    /// Creates ItemAttributes for a regular file with parent_id.
    fn make_file_attrs_with_parent(
        &self,
        item_id: u64,
        size: u64,
        parent_id: Option<u64>,
    ) -> ItemAttributes {
        let now = std::time::SystemTime::now();
        let timestamp = prost_types::Timestamp::from(now);
        ItemAttributes {
            file_id: Some(item_id),
            parent_id,
            uid: Some(self.uid),
            gid: Some(self.gid),
            mode: Some(DEFAULT_FILE_PERM as u32 | libc::S_IFREG as u32),
            r#type: Some(ItemType::File.into()),
            link_count: Some(1),
            size: Some(size),
            alloc_size: Some(size.div_ceil(BLOCK_SIZE) * BLOCK_SIZE),
            access_time: Some(timestamp),
            modify_time: Some(timestamp),
            change_time: Some(timestamp),
            birth_time: Some(timestamp),
            added_time: Some(timestamp),
            backup_time: None,
            flags: Some(0),
            supports_limited_xattrs: Some(false),
            inhibit_kernel_offloaded_io: Some(false),
        }
    }

    /// Creates ItemAttributes for a symbolic link.
    fn make_symlink_attrs(&self, item_id: u64, target_len: u64) -> ItemAttributes {
        self.make_symlink_attrs_with_parent(item_id, target_len, None)
    }

    /// Creates ItemAttributes for a symbolic link with parent_id.
    fn make_symlink_attrs_with_parent(
        &self,
        item_id: u64,
        target_len: u64,
        parent_id: Option<u64>,
    ) -> ItemAttributes {
        let now = std::time::SystemTime::now();
        let timestamp = prost_types::Timestamp::from(now);
        ItemAttributes {
            file_id: Some(item_id),
            parent_id,
            uid: Some(self.uid),
            gid: Some(self.gid),
            mode: Some(0o777 | libc::S_IFLNK as u32),
            r#type: Some(ItemType::Symlink.into()),
            link_count: Some(1),
            size: Some(target_len),
            alloc_size: Some(0),
            access_time: Some(timestamp),
            modify_time: Some(timestamp),
            change_time: Some(timestamp),
            birth_time: Some(timestamp),
            added_time: Some(timestamp),
            backup_time: None,
            flags: Some(0),
            supports_limited_xattrs: Some(false),
            inhibit_kernel_offloaded_io: Some(false),
        }
    }

    /// Helper to create an Item with name and attributes.
    fn make_item(&self, name: &str, attrs: ItemAttributes) -> Item {
        Item {
            name: name.as_bytes().to_vec(),
            attributes: Some(attrs),
        }
    }

    /// Run an async vault operation on the tokio runtime.
    ///
    /// Spawns the operation as a new task, keeping FSKit dispatch threads free.
    /// Requires a tokio runtime to be running (guaranteed by `#[tokio::main]` in main.rs).
    async fn run_vault_op<T, F, Fut>(&self, f: F) -> Result<T, FsKitError>
    where
        T: Send + 'static,
        F: FnOnce(Arc<VaultOperationsAsync>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = T> + Send + 'static,
    {
        let ops = Arc::clone(&self.ops);
        tokio::spawn(f(ops))
            .await
            .map_err(|e| {
                error!(error = %e, "tokio::spawn failed");
                FsKitError::Posix(libc::EIO)
            })
    }
}

#[async_trait]
impl Filesystem for CryptomatorFSKit {
    /// Get the resource identifier and name.
    async fn get_resource_identifier(&mut self) -> FsKitResult<ResourceIdentifier> {
        Ok(ResourceIdentifier {
            name: Some("Cryptomator Vault".into()),
            container_id: Some("cryptomator-vault".into()),
        })
    }

    /// Get the volume identifier and name.
    async fn get_volume_identifier(&mut self) -> FsKitResult<VolumeIdentifier> {
        Ok(VolumeIdentifier {
            id: Some(self.volume_id.clone()),
            name: Some("Vault".into()),
        })
    }

    /// Get volume behavior options.
    async fn get_volume_behavior(&mut self) -> FsKitResult<VolumeBehavior> {
        Ok(VolumeBehavior {
            enable_open_unlink_emulation: Some(true),
            xattr_operations_inhibited: Some(true), // No xattr support yet
            is_open_close_inhibited: Some(false),
            is_access_check_inhibited: Some(false),
            is_volume_rename_inhibited: Some(true), // Can't rename vault
            is_preallocate_inhibited: Some(false),
            item_deactivation_options: vec![],
        })
    }

    /// Get path configuration properties.
    async fn get_path_conf_operations(&mut self) -> FsKitResult<PathConfOperations> {
        Ok(PathConfOperations {
            maximum_link_count: 1, // No hard links
            maximum_name_length: 255,
            restricts_ownership_changes: true,
            truncates_long_names: false,
            maximum_xattr_size: Some(65536),
            maximum_xattr_size_in_bits: None,
            maximum_file_size: Some(u64::MAX),
            maximum_file_size_in_bits: None,
        })
    }

    /// Get volume capabilities.
    async fn get_volume_capabilities(&mut self) -> FsKitResult<SupportedCapabilities> {
        Ok(SupportedCapabilities {
            supports_persistent_object_ids: Some(false),
            supports_symbolic_links: Some(true),
            supports_hard_links: Some(false),
            supports_journal: Some(false),
            supports_active_journal: Some(false),
            does_not_support_root_times: Some(false),
            supports_sparse_files: Some(false),
            supports_zero_runs: Some(false),
            supports_fast_statfs: Some(true),
            supports_2tb_files: Some(true),
            supports_open_deny_modes: Some(false),
            supports_hidden_files: Some(false),
            does_not_support_volume_sizes: Some(false),
            supports_64bit_object_ids: Some(true),
            supports_document_id: Some(false),
            does_not_support_immutable_files: Some(true),
            does_not_support_setting_file_permissions: Some(true),
            supports_shared_space: Some(false),
            supports_volume_groups: Some(false),
            case_format: Some(CaseFormat::Sensitive.into()),
        })
    }

    /// Get volume statistics.
    async fn get_volume_statistics(&mut self) -> FsKitResult<StatFsResult> {
        // Query real filesystem statistics from underlying storage
        match nix::sys::statvfs::statvfs(&self.vault_path) {
            Ok(stat) => {
                let block_size = stat.fragment_size() as i64;
                let total_blocks = stat.blocks() as u64;
                let free_blocks = stat.blocks_free() as u64;
                let available_blocks = stat.blocks_available() as u64;
                let used_blocks = total_blocks.saturating_sub(free_blocks);

                let total_bytes = total_blocks * block_size as u64;
                let free_bytes = free_blocks * block_size as u64;
                let available_bytes = available_blocks * block_size as u64;
                let used_bytes = used_blocks * block_size as u64;

                Ok(StatFsResult {
                    block_size,
                    io_size: block_size,
                    total_blocks,
                    available_blocks,
                    free_blocks,
                    used_blocks,
                    total_bytes,
                    available_bytes,
                    free_bytes,
                    used_bytes,
                    total_files: stat.files() as u64,
                    free_files: stat.files_free() as u64,
                })
            }
            Err(e) => {
                debug!(error = %e, "Failed to get statvfs, using defaults");
                Ok(StatFsResult {
                    block_size: BLOCK_SIZE as i64,
                    io_size: BLOCK_SIZE as i64,
                    total_blocks: 1000000,
                    available_blocks: 500000,
                    free_blocks: 500000,
                    used_blocks: 500000,
                    total_bytes: 1000000 * BLOCK_SIZE,
                    available_bytes: 500000 * BLOCK_SIZE,
                    free_bytes: 500000 * BLOCK_SIZE,
                    used_bytes: 500000 * BLOCK_SIZE,
                    total_files: 1000000,
                    free_files: 500000,
                })
            }
        }
    }

    /// Mount the volume.
    async fn mount(&mut self, _options: TaskOptions) -> FsKitResult<()> {
        tracing::info!("FSKit filesystem mounted");
        Ok(())
    }

    /// Unmount the volume.
    async fn unmount(&mut self) -> FsKitResult<()> {
        tracing::info!("FSKit filesystem unmounted");
        Ok(())
    }

    /// Synchronize the volume.
    async fn synchronize(&mut self, _flags: SyncFlags) -> FsKitResult<()> {
        // Cryptomator writes are synchronous, nothing to flush
        Ok(())
    }

    /// Activate the volume and return the root item.
    async fn activate(&mut self, _options: TaskOptions) -> FsKitResult<Item> {
        tracing::info!("FSKit filesystem activated");
        let mut attrs = self.make_dir_attrs(ROOT_ITEM_ID);
        attrs.parent_id = Some(ROOT_ITEM_ID);
        Ok(Item {
            name: Vec::new(),
            attributes: Some(attrs),
        })
    }

    /// Deactivate the volume.
    async fn deactivate(&mut self) -> FsKitResult<()> {
        tracing::info!("FSKit filesystem deactivated");
        Ok(())
    }

    /// Look up an item within a directory.
    async fn lookup_item(&mut self, name: &OsStr, directory_id: u64) -> FsKitResult<Item> {
        let name_str = name.to_str().ok_or(FsKitError::Posix(libc::EINVAL))?;

        trace!(parent = directory_id, name = name_str, "lookup_item");

        // Get parent directory
        let dir_entry = self
            .items
            .get(directory_id)
            .ok_or(FsKitError::Posix(libc::ENOENT))?;

        let dir_id = dir_entry.dir_id().ok_or(FsKitError::Posix(libc::ENOTDIR))?;
        let parent_path = dir_entry.path.clone();
        drop(dir_entry);

        // Use O(1) lookups instead of list_all() + linear search
        // Try file first (most common case)
        let name_owned = name_str.to_string();
        let dir_id_clone = dir_id.clone();
        if let Some(file_info) = self
            .run_vault_op(move |ops| async move { ops.find_file(&dir_id_clone, &name_owned).await })
            .await?
            .map_err(|e| FsKitError::Posix(operation_error_to_errno(&e)))?
        {
            let child_path = parent_path.join(name_str);
            let kind = ItemKind::File {
                dir_id: dir_id.clone(),
                name: name_str.to_string(),
            };
            let item_id = self.items.get_or_insert(child_path, kind);
            let size = encrypted_to_plaintext_size_or_zero(file_info.encrypted_size);
            let attrs = self.make_file_attrs_with_parent(item_id, size, Some(directory_id));
            return Ok(self.make_item(name_str, attrs));
        }

        // Try directory
        let name_owned = name_str.to_string();
        let dir_id_clone = dir_id.clone();
        if let Some(dir_info) = self
            .run_vault_op(move |ops| async move { ops.find_directory(&dir_id_clone, &name_owned).await })
            .await?
            .map_err(|e| FsKitError::Posix(operation_error_to_errno(&e)))?
        {
            let child_path = parent_path.join(name_str);
            let kind = ItemKind::Directory {
                dir_id: dir_info.directory_id.clone(),
            };
            let item_id = self.items.get_or_insert(child_path, kind);
            let attrs = self.make_dir_attrs_with_parent(item_id, Some(directory_id));
            return Ok(self.make_item(name_str, attrs));
        }

        // Try symlink
        let name_owned = name_str.to_string();
        let dir_id_clone = dir_id.clone();
        if let Some(symlink_info) = self
            .run_vault_op(move |ops| async move { ops.find_symlink(&dir_id_clone, &name_owned).await })
            .await?
            .map_err(|e| FsKitError::Posix(operation_error_to_errno(&e)))?
        {
            let child_path = parent_path.join(name_str);
            let kind = ItemKind::Symlink {
                dir_id: dir_id.clone(),
                name: name_str.to_string(),
            };
            let item_id = self.items.get_or_insert(child_path, kind);
            let attrs = self.make_symlink_attrs_with_parent(
                item_id,
                symlink_info.target.len() as u64,
                Some(directory_id),
            );
            return Ok(self.make_item(name_str, attrs));
        }

        // Not found
        Err(FsKitError::Posix(libc::ENOENT))
    }

    /// Get attributes for an item.
    async fn get_attributes(&mut self, item_id: u64) -> FsKitResult<ItemAttributes> {
        trace!(item_id = item_id, "get_attributes");

        // Check cache first for files and symlinks
        if let Some(cached) = self.attr_cache.get(item_id) {
            trace!(item_id = item_id, "attr cache hit");
            return Ok(cached.value);
        }

        let entry = self
            .items
            .get(item_id)
            .ok_or(FsKitError::Posix(libc::ENOENT))?;

        match &entry.kind {
            ItemKind::Root => {
                let attrs = self.make_dir_attrs(item_id);
                self.attr_cache.insert(item_id, attrs);
                Ok(attrs)
            }
            ItemKind::Directory { .. } => {
                let attrs = self.make_dir_attrs(item_id);
                self.attr_cache.insert(item_id, attrs);
                Ok(attrs)
            }
            ItemKind::File { dir_id, name } => {
                let dir_id = dir_id.clone();
                let name = name.clone();
                drop(entry);

                // Use O(1) find_file instead of list_files + linear search
                let file_info = self
                    .run_vault_op(move |ops| async move { ops.find_file(&dir_id, &name).await })
                    .await?
                    .map_err(|e| FsKitError::Posix(operation_error_to_errno(&e)))?
                    .ok_or(FsKitError::Posix(libc::ENOENT))?;

                let size = encrypted_to_plaintext_size_or_zero(file_info.encrypted_size);
                let attrs = self.make_file_attrs(item_id, size);
                self.attr_cache.insert(item_id, attrs);
                Ok(attrs)
            }
            ItemKind::Symlink { dir_id, name } => {
                let dir_id = dir_id.clone();
                let name = name.clone();
                drop(entry);

                let target = self
                    .run_vault_op(move |ops| async move { ops.read_symlink(&dir_id, &name).await })
                    .await?
                    .map_err(|e| FsKitError::Posix(operation_error_to_errno(&e)))?;

                let attrs = self.make_symlink_attrs(item_id, target.len() as u64);
                self.attr_cache.insert(item_id, attrs);
                Ok(attrs)
            }
        }
    }

    /// Set attributes for an item.
    async fn set_attributes(
        &mut self,
        item_id: u64,
        attributes: ItemAttributes,
    ) -> FsKitResult<ItemAttributes> {
        trace!(item_id = item_id, "set_attributes");

        // Cryptomator doesn't support changing permissions/ownership
        // Only handle size changes (truncate)

        if let Some(new_size) = attributes.size {
            let entry = self
                .items
                .get(item_id)
                .ok_or(FsKitError::Posix(libc::ENOENT))?;

            if let ItemKind::File { dir_id, name } = &entry.kind {
                let dir_id = dir_id.clone();
                let name = name.clone();
                drop(entry);

                // Check if we have an open handle
                if let Some(mut handle) = self.handles.get_mut(&item_id)
                    && let Some(buffer) = handle.as_write_buffer_mut() {
                        buffer.truncate(new_size);
                        drop(handle);
                        let attrs = self.make_file_attrs(item_id, new_size);
                        self.attr_cache.insert(item_id, attrs);
                        return Ok(attrs);
                    }

                // No open handle - read file, truncate, write back
                let dir_id_clone = dir_id.clone();
                let name_clone = name.clone();
                let mut content = self
                    .run_vault_op(move |ops| async move {
                        ops.read_file(&dir_id_clone, &name_clone)
                            .await
                            .map(|f| f.content)
                            .unwrap_or_default()
                    })
                    .await?;

                content.resize(new_size as usize, 0);

                self.run_vault_op(move |ops| async move {
                    ops.write_file(&dir_id, &name, &content).await
                })
                .await?
                .map_err(|e| FsKitError::Posix(write_error_to_errno(&e)))?;

                let attrs = self.make_file_attrs(item_id, new_size);
                self.attr_cache.insert(item_id, attrs);
                return Ok(attrs);
            }
        }

        // Return current attributes for unsupported changes
        self.get_attributes(item_id).await
    }

    /// Reclaim an item (called when system no longer needs it).
    async fn reclaim_item(&mut self, item_id: u64) -> FsKitResult<()> {
        trace!(item_id = item_id, "reclaim_item");
        self.attr_cache.invalidate(item_id);
        self.items.reclaim(item_id);
        Ok(())
    }

    /// Deactivate an item.
    async fn deactivate_item(&mut self, item_id: u64) -> FsKitResult<()> {
        trace!(item_id = item_id, "deactivate_item");
        // Nothing to do - items are cleaned up on reclaim
        Ok(())
    }

    /// Read a symbolic link.
    async fn read_symbolic_link(&mut self, item_id: u64) -> FsKitResult<Vec<u8>> {
        trace!(item_id = item_id, "read_symbolic_link");

        let entry = self
            .items
            .get(item_id)
            .ok_or(FsKitError::Posix(libc::ENOENT))?;

        let (dir_id, name) = match &entry.kind {
            ItemKind::Symlink { dir_id, name } => (dir_id.clone(), name.clone()),
            _ => return Err(FsKitError::Posix(libc::EINVAL)),
        };
        drop(entry);

        let target = self
            .run_vault_op(move |ops| async move { ops.read_symlink(&dir_id, &name).await })
            .await?
            .map_err(|e| FsKitError::Posix(operation_error_to_errno(&e)))?;

        Ok(target.into_bytes())
    }

    /// Create a new file or directory.
    async fn create_item(
        &mut self,
        name: &OsStr,
        r#type: ItemType,
        directory_id: u64,
        _attributes: ItemAttributes,
    ) -> FsKitResult<Item> {
        let name_str = name.to_str().ok_or(FsKitError::Posix(libc::EINVAL))?;

        trace!(
            parent = directory_id,
            name = name_str,
            item_type = ?r#type,
            "create_item"
        );

        let dir_entry = self
            .items
            .get(directory_id)
            .ok_or(FsKitError::Posix(libc::ENOENT))?;

        let parent_dir_id = dir_entry
            .dir_id()
            .ok_or(FsKitError::Posix(libc::ENOTDIR))?;
        let parent_path = dir_entry.path.clone();
        drop(dir_entry);

        match r#type {
            ItemType::Directory => {
                let parent_dir_id_clone = parent_dir_id.clone();
                let name_owned = name_str.to_string();
                let new_dir_id = self
                    .run_vault_op(move |ops| async move {
                        ops.create_directory(&parent_dir_id_clone, &name_owned).await
                    })
                    .await?
                    .map_err(|e| FsKitError::Posix(write_error_to_errno(&e)))?;

                let child_path = parent_path.join(name_str);
                let item_id = self.items.get_or_insert(
                    child_path,
                    ItemKind::Directory { dir_id: new_dir_id },
                );

                let attrs = self.make_dir_attrs_with_parent(item_id, Some(directory_id));
                Ok(self.make_item(name_str, attrs))
            }
            ItemType::File => {
                // Create an empty file
                let parent_dir_id_clone = parent_dir_id.clone();
                let name_owned = name_str.to_string();
                self.run_vault_op(move |ops| async move {
                    ops.write_file(&parent_dir_id_clone, &name_owned, &[]).await
                })
                .await?
                .map_err(|e| FsKitError::Posix(write_error_to_errno(&e)))?;

                let child_path = parent_path.join(name_str);
                let item_id = self.items.get_or_insert(
                    child_path,
                    ItemKind::File {
                        dir_id: parent_dir_id,
                        name: name_str.to_string(),
                    },
                );

                let attrs = self.make_file_attrs_with_parent(item_id, 0, Some(directory_id));
                Ok(self.make_item(name_str, attrs))
            }
            _ => Err(FsKitError::Posix(libc::ENOTSUP)),
        }
    }

    /// Create a symbolic link.
    async fn create_symbolic_link(
        &mut self,
        name: &OsStr,
        directory_id: u64,
        _attributes: ItemAttributes,
        contents: Vec<u8>,
    ) -> FsKitResult<Item> {
        let name_str = name.to_str().ok_or(FsKitError::Posix(libc::EINVAL))?;
        let target =
            String::from_utf8(contents).map_err(|_| FsKitError::Posix(libc::EINVAL))?;

        trace!(
            parent = directory_id,
            name = name_str,
            target = target,
            "create_symbolic_link"
        );

        let dir_entry = self
            .items
            .get(directory_id)
            .ok_or(FsKitError::Posix(libc::ENOENT))?;

        let parent_dir_id = dir_entry
            .dir_id()
            .ok_or(FsKitError::Posix(libc::ENOTDIR))?;
        let parent_path = dir_entry.path.clone();
        drop(dir_entry);

        let parent_dir_id_clone = parent_dir_id.clone();
        let name_owned = name_str.to_string();
        let target_clone = target.clone();
        self.run_vault_op(move |ops| async move {
            ops.create_symlink(&parent_dir_id_clone, &name_owned, &target_clone)
                .await
        })
        .await?
        .map_err(|e| FsKitError::Posix(write_error_to_errno(&e)))?;

        let child_path = parent_path.join(name_str);
        let item_id = self.items.get_or_insert(
            child_path,
            ItemKind::Symlink {
                dir_id: parent_dir_id,
                name: name_str.to_string(),
            },
        );

        let attrs =
            self.make_symlink_attrs_with_parent(item_id, target.len() as u64, Some(directory_id));
        Ok(self.make_item(name_str, attrs))
    }

    /// Create a hard link (not supported).
    async fn create_link(
        &mut self,
        _item_id: u64,
        _name: &OsStr,
        _directory_id: u64,
    ) -> FsKitResult<Vec<u8>> {
        // Cryptomator doesn't support hard links
        Err(FsKitError::Posix(libc::ENOTSUP))
    }

    /// Remove an item.
    async fn remove_item(
        &mut self,
        item_id: u64,
        _name: &OsStr,
        _directory_id: u64,
    ) -> FsKitResult<()> {
        trace!(item_id = item_id, "remove_item");

        let entry = self
            .items
            .get(item_id)
            .ok_or(FsKitError::Posix(libc::ENOENT))?;

        let path = entry.path.clone();
        match &entry.kind {
            ItemKind::Root => {
                return Err(FsKitError::Posix(libc::EPERM));
            }
            ItemKind::Directory { dir_id: _ } => {
                drop(entry);

                // For directories, we need the parent's dir_id
                let parent_path = path.parent();
                if let Some(parent) = parent_path
                    && let Some(parent_id) = self.items.get_id(&parent)
                        && let Some(parent_entry) = self.items.get(parent_id)
                            && let Some(parent_dir_id) = parent_entry.dir_id() {
                                let name = path.file_name().unwrap_or_default().to_string();
                                self.run_vault_op(move |ops| async move {
                                    ops.delete_directory(&parent_dir_id, &name).await
                                })
                                .await?
                                .map_err(|e| FsKitError::Posix(write_error_to_errno(&e)))?;
                            }
            }
            ItemKind::File { dir_id, name } => {
                let dir_id = dir_id.clone();
                let name = name.clone();
                drop(entry);

                self.run_vault_op(move |ops| async move {
                    ops.delete_file(&dir_id, &name).await
                })
                .await?
                .map_err(|e| FsKitError::Posix(write_error_to_errno(&e)))?;
            }
            ItemKind::Symlink { dir_id, name } => {
                let dir_id = dir_id.clone();
                let name = name.clone();
                drop(entry);

                self.run_vault_op(move |ops| async move {
                    ops.delete_symlink(&dir_id, &name).await
                })
                .await?
                .map_err(|e| FsKitError::Posix(write_error_to_errno(&e)))?;
            }
        }

        self.attr_cache.invalidate(item_id);
        self.items.invalidate_path(&path);
        Ok(())
    }

    /// Rename an item.
    async fn rename_item(
        &mut self,
        item_id: u64,
        source_directory_id: u64,
        _source_name: &OsStr,
        destination_name: &OsStr,
        destination_directory_id: u64,
        _over_item_id: Option<u64>,
    ) -> FsKitResult<Vec<u8>> {
        let dest_name_str = destination_name
            .to_str()
            .ok_or(FsKitError::Posix(libc::EINVAL))?;

        trace!(
            item_id = item_id,
            dest_name = dest_name_str,
            "rename_item"
        );

        let entry = self
            .items
            .get(item_id)
            .ok_or(FsKitError::Posix(libc::ENOENT))?;

        let old_path = entry.path.clone();
        let (src_dir_id, name) = match &entry.kind {
            ItemKind::File { dir_id, name } | ItemKind::Symlink { dir_id, name } => {
                (dir_id.clone(), name.clone())
            }
            ItemKind::Directory { .. } => {
                // Get name from path
                let name = old_path
                    .file_name()
                    .ok_or(FsKitError::Posix(libc::EINVAL))?;
                // Get parent dir_id
                let parent_entry = self
                    .items
                    .get(source_directory_id)
                    .ok_or(FsKitError::Posix(libc::ENOENT))?;
                let dir_id = parent_entry
                    .dir_id()
                    .ok_or(FsKitError::Posix(libc::ENOTDIR))?;
                (dir_id, name.to_string())
            }
            ItemKind::Root => return Err(FsKitError::Posix(libc::EPERM)),
        };
        drop(entry);

        // Get destination directory info
        let dest_entry = self
            .items
            .get(destination_directory_id)
            .ok_or(FsKitError::Posix(libc::ENOENT))?;
        let dest_dir_id = dest_entry
            .dir_id()
            .ok_or(FsKitError::Posix(libc::ENOTDIR))?;
        let dest_parent_path = dest_entry.path.clone();
        drop(dest_entry);

        // Perform rename/move
        let dest_name_owned = dest_name_str.to_string();
        if source_directory_id == destination_directory_id {
            // Same directory - just rename
            self.run_vault_op(move |ops| async move {
                ops.rename_file(&src_dir_id, &name, &dest_name_owned).await
            })
            .await?
            .map_err(|e| FsKitError::Posix(write_error_to_errno(&e)))?;
        } else if name == dest_name_str {
            // Different directories, same name - just move
            self.run_vault_op(move |ops| async move {
                ops.move_file(&src_dir_id, &name, &dest_dir_id).await
            })
            .await?
            .map_err(|e| FsKitError::Posix(write_error_to_errno(&e)))?;
        } else {
            // Different directories, different name - atomic move+rename
            self.run_vault_op(move |ops| async move {
                ops.move_and_rename_file(&src_dir_id, &name, &dest_dir_id, &dest_name_owned)
                    .await
            })
            .await?
            .map_err(|e| FsKitError::Posix(write_error_to_errno(&e)))?;
        }

        // Update item table and invalidate cache
        let new_path = dest_parent_path.join(dest_name_str);
        self.items.update_path(item_id, &old_path, new_path);
        self.attr_cache.invalidate(item_id);

        Ok(dest_name_str.as_bytes().to_vec())
    }

    /// Enumerate directory contents.
    async fn enumerate_directory(
        &mut self,
        directory_id: u64,
        cookie: u64,
        _verifier: u64,
    ) -> FsKitResult<DirectoryEntries> {
        trace!(
            directory_id = directory_id,
            cookie = cookie,
            "enumerate_directory"
        );

        let dir_entry = self
            .items
            .get(directory_id)
            .ok_or(FsKitError::Posix(libc::ENOENT))?;

        let dir_id = dir_entry.dir_id().ok_or(FsKitError::Posix(libc::ENOTDIR))?;
        let current_path = dir_entry.path.clone();
        drop(dir_entry);

        let dir_id_clone = dir_id.clone();
        let (files, dirs, symlinks) = self
            .run_vault_op(move |ops| async move { ops.list_all(&dir_id_clone).await })
            .await?
            .map_err(|e| FsKitError::Posix(operation_error_to_errno(&e)))?;

        // Build (name, ItemKind, size) tuples first, then process in a single loop
        // This consolidates the three separate loops into one unified iteration
        enum EntryData {
            Dir { name: String, sub_dir_id: oxidized_cryptolib::vault::DirId },
            File { name: String, size: u64 },
            Symlink { name: String, target_len: u64 },
        }

        let entry_data: Vec<EntryData> = dirs
            .into_iter()
            .map(|d| EntryData::Dir { name: d.name, sub_dir_id: d.directory_id })
            .chain(files.into_iter().map(|f| EntryData::File {
                name: f.name,
                size: encrypted_to_plaintext_size_or_zero(f.encrypted_size),
            }))
            .chain(symlinks.into_iter().map(|s| EntryData::Symlink {
                name: s.name,
                target_len: s.target.len() as u64,
            }))
            .collect();

        let mut all_entries = Vec::with_capacity(entry_data.len());
        for data in entry_data {
            let (name, item) = match data {
                EntryData::Dir { name, sub_dir_id } => {
                    let child_path = current_path.join(&name);
                    let item_id = self.items.get_or_insert(
                        child_path,
                        ItemKind::Directory { dir_id: sub_dir_id },
                    );
                    let attrs = self.make_dir_attrs_with_parent(item_id, Some(directory_id));
                    (name.clone(), self.make_item(&name, attrs))
                }
                EntryData::File { name, size } => {
                    let child_path = current_path.join(&name);
                    let item_id = self.items.get_or_insert(
                        child_path,
                        ItemKind::File {
                            dir_id: dir_id.clone(),
                            name: name.clone(),
                        },
                    );
                    let attrs = self.make_file_attrs_with_parent(item_id, size, Some(directory_id));
                    (name.clone(), self.make_item(&name, attrs))
                }
                EntryData::Symlink { name, target_len } => {
                    let child_path = current_path.join(&name);
                    let item_id = self.items.get_or_insert(
                        child_path,
                        ItemKind::Symlink {
                            dir_id: dir_id.clone(),
                            name: name.clone(),
                        },
                    );
                    let attrs = self.make_symlink_attrs_with_parent(item_id, target_len, Some(directory_id));
                    (name.clone(), self.make_item(&name, attrs))
                }
            };
            all_entries.push((name, item));
        }

        // Apply pagination via cookie and build Entry structs
        let entries: Vec<_> = all_entries
            .into_iter()
            .skip(cookie as usize)
            .enumerate()
            .map(|(idx, (_name, item))| directory_entries::Entry {
                item: Some(item),
                next_cookie: (cookie as usize + idx + 1) as u64,
            })
            .collect();

        Ok(DirectoryEntries {
            entries,
            verifier: 0,
        })
    }

    /// Get supported xattr names (not implemented).
    async fn get_supported_xattr_names(&mut self, _item_id: u64) -> FsKitResult<Xattrs> {
        Ok(Xattrs { names: vec![] })
    }

    /// Get xattr value (not implemented).
    async fn get_xattr(&mut self, _name: &OsStr, _item_id: u64) -> FsKitResult<Vec<u8>> {
        Err(FsKitError::Posix(libc::ENOTSUP))
    }

    /// Set xattr value (not implemented).
    async fn set_xattr(
        &mut self,
        _name: &OsStr,
        _value: Option<Vec<u8>>,
        _item_id: u64,
        _policy: SetXattrPolicy,
    ) -> FsKitResult<()> {
        Err(FsKitError::Posix(libc::ENOTSUP))
    }

    /// Get all xattrs (not implemented).
    async fn get_xattrs(&mut self, _item_id: u64) -> FsKitResult<Xattrs> {
        Ok(Xattrs { names: vec![] })
    }

    /// Open a file for access.
    async fn open_item(&mut self, item_id: u64, modes: Vec<OpenMode>) -> FsKitResult<()> {
        trace!(item_id = item_id, modes = ?modes, "open_item");

        let entry = self
            .items
            .get(item_id)
            .ok_or(FsKitError::Posix(libc::ENOENT))?;

        let (dir_id, name) = match &entry.kind {
            ItemKind::File { dir_id, name } => (dir_id.clone(), name.clone()),
            ItemKind::Directory { .. } | ItemKind::Root => {
                return Err(FsKitError::Posix(libc::EISDIR))
            }
            ItemKind::Symlink { .. } => return Err(FsKitError::Posix(libc::EINVAL)),
        };
        drop(entry);

        let is_write = modes.iter().any(|m| matches!(m, OpenMode::Write));

        if is_write {
            // Load existing content for random-write support
            let dir_id_clone = dir_id.clone();
            let name_clone = name.clone();
            let existing_content = self
                .run_vault_op(move |ops| async move {
                    ops.read_file(&dir_id_clone, &name_clone)
                        .await
                        .map(|f| f.content)
                        .unwrap_or_default()
                })
                .await?;

            let buffer = WriteBuffer::new(dir_id, name, existing_content);
            self.handles.insert(item_id, FsKitHandle::WriteBuffer(buffer));
        } else {
            // Open for reading
            let reader = self
                .run_vault_op(move |ops| async move { ops.open_file(&dir_id, &name).await })
                .await?
                .map_err(|e| FsKitError::Posix(operation_error_to_errno(&e)))?;
            self.handles.insert(item_id, FsKitHandle::Reader(Box::new(reader)));
        }

        self.stats.record_file_open();
        Ok(())
    }

    /// Close a file.
    async fn close_item(&mut self, item_id: u64, _modes: Vec<OpenMode>) -> FsKitResult<()> {
        trace!(item_id = item_id, "close_item");

        if let Some(handle) = self.handles.remove(&item_id)
            && let FsKitHandle::WriteBuffer(buffer) = handle
                && buffer.is_dirty() {
                    let dir_id = buffer.dir_id().clone();
                    let filename = buffer.filename().to_string();
                    let content = buffer.into_content();
                    let content_len = content.len();

                    self.stats.start_write();
                    let start = Instant::now();
                    let result = self.run_vault_op(move |ops| async move {
                        ops.write_file(&dir_id, &filename, &content).await
                    })
                    .await;

                    match result {
                        Ok(Ok(_)) => {
                            let elapsed = start.elapsed();
                            self.stats.finish_write();
                            self.stats.record_write(content_len as u64);
                            self.stats.record_write_latency(elapsed);
                            self.stats.record_encrypted(content_len as u64);
                        }
                        Ok(Err(e)) => {
                            self.stats.finish_write();
                            self.stats.record_write_latency(start.elapsed());
                            return Err(FsKitError::Posix(write_error_to_errno(&e)));
                        }
                        Err(e) => {
                            self.stats.finish_write();
                            self.stats.record_write_latency(start.elapsed());
                            return Err(e);
                        }
                    }

                    // Invalidate cache - size has changed
                    self.attr_cache.invalidate(item_id);

                    debug!(item_id = item_id, size = content_len, "WriteBuffer flushed");
                }

        self.stats.record_file_close();
        Ok(())
    }

    /// Read from a file.
    async fn read(&mut self, item_id: u64, offset: i64, length: i64) -> FsKitResult<Vec<u8>> {
        trace!(
            item_id = item_id,
            offset = offset,
            length = length,
            "read"
        );

        self.stats.start_read();

        let mut handle = self
            .handles
            .get_mut(&item_id)
            .ok_or_else(|| {
                self.stats.finish_read();
                FsKitError::Posix(libc::EBADF)
            })?;

        match &mut *handle {
            FsKitHandle::Reader(reader) => {
                let start = Instant::now();
                let result = reader
                    .read_range(offset as u64, length as usize)
                    .await
                    .map_err(|e| {
                        self.stats.finish_read();
                        self.stats.record_read_latency(start.elapsed());
                        error!(error = %e, "Read failed");
                        FsKitError::Posix(libc::EIO)
                    })?;
                let elapsed = start.elapsed();
                let bytes_read = result.len() as u64;
                self.stats.finish_read();
                self.stats.record_read(bytes_read);
                self.stats.record_read_latency(elapsed);
                self.stats.record_decrypted(bytes_read);
                Ok(result)
            }
            FsKitHandle::WriteBuffer(buffer) => {
                let data = buffer.read(offset as u64, length as usize).to_vec();
                let bytes_read = data.len() as u64;
                self.stats.finish_read();
                self.stats.record_read(bytes_read);
                self.stats.record_decrypted(bytes_read);
                Ok(data)
            }
        }
    }

    /// Write to a file.
    async fn write(&mut self, contents: Vec<u8>, item_id: u64, offset: i64) -> FsKitResult<i64> {
        trace!(
            item_id = item_id,
            offset = offset,
            size = contents.len(),
            "write"
        );

        self.stats.start_write();

        let mut handle = self
            .handles
            .get_mut(&item_id)
            .ok_or_else(|| {
                self.stats.finish_write();
                FsKitError::Posix(libc::EBADF)
            })?;

        let buffer = handle
            .as_write_buffer_mut()
            .ok_or_else(|| {
                self.stats.finish_write();
                FsKitError::Posix(libc::EBADF)
            })?;

        let bytes_written = buffer.write(offset as u64, &contents);
        self.stats.finish_write();
        self.stats.record_write(bytes_written as u64);
        self.stats.record_encrypted(bytes_written as u64);
        Ok(bytes_written as i64)
    }

    /// Check access permissions.
    async fn check_access(&mut self, item_id: u64, _access: Vec<AccessMask>) -> FsKitResult<bool> {
        // All files are owned by the mounting user with full access
        if self.items.get(item_id).is_some() {
            Ok(true)
        } else {
            Err(FsKitError::Posix(libc::ENOENT))
        }
    }

    /// Set volume name.
    async fn set_volume_name(&mut self, name: Vec<u8>) -> FsKitResult<Vec<u8>> {
        // Accept but ignore - Cryptomator vault name is fixed
        Ok(name)
    }

    /// Preallocate space for a file.
    async fn preallocate_space(
        &mut self,
        item_id: u64,
        offset: i64,
        length: i64,
        _flags: Vec<PreallocateFlag>,
    ) -> FsKitResult<i64> {
        trace!(
            item_id = item_id,
            offset = offset,
            length = length,
            "preallocate_space"
        );

        let new_size = (offset + length) as u64;

        // If we have an open handle, extend the buffer
        if let Some(mut handle) = self.handles.get_mut(&item_id)
            && let Some(buffer) = handle.as_write_buffer_mut() {
                if new_size > buffer.len() {
                    buffer.truncate(new_size);
                }
                return Ok(new_size as i64);
            }

        // No open handle - use set_attributes to truncate
        let attrs = ItemAttributes {
            size: Some(new_size),
            ..Default::default()
        };
        self.set_attributes(item_id, attrs).await?;
        Ok(new_size as i64)
    }
}
