# oxcrypt-mount

Shared utilities and interfaces for Cryptomator vault mount backends.

Provides the common infrastructure used by all mount backends (FUSE, FSKit, WebDAV, NFS):

- **MountBackend trait** - unified interface for all filesystem backends
- **WriteBuffer** - read-modify-write pattern for AES-GCM encrypted chunks
- **HandleTable** - thread-safe file handle management
- **Moka cache** - TTL-based attribute and entry caching
- **Error mapping** - errno and HTTP status classification

## License

Licensed under the Mozilla Public License 2.0.
