// OxVaultServiceProtocol.h
// Objective-C protocol definition for XPC interface.
// This must be linked into Rust clients so NSXPCConnection can properly
// serialize/deserialize XPC messages.

#import <Foundation/Foundation.h>

/// XPC Protocol for the OxCrypt FSKit service.
/// Matches the Swift protocol in Shared/OxVaultServiceProtocol.swift
@protocol OxVaultServiceProtocol <NSObject>

/// Mount a vault at the given path.
/// @param vaultPath Absolute path to the vault directory
/// @param password Vault password
/// @param reply Completion handler with mountpoint (String?) or error (NSError?)
- (void)mountWithVaultPath:(NSString *)vaultPath
                  password:(NSString *)password
                     reply:(void (^)(NSString * _Nullable mountpoint, NSError * _Nullable error))reply;

/// Unmount a mounted vault.
/// @param mountpoint The mountpoint to unmount
/// @param reply Completion handler with optional error
- (void)unmountWithMountpoint:(NSString *)mountpoint
                        reply:(void (^)(NSError * _Nullable error))reply;

/// List all active mounts.
/// @param reply Completion handler with array of mount dictionaries
- (void)listMountsWithReply:(void (^)(NSArray<NSDictionary<NSString *, id> *> * _Nullable mounts, NSError * _Nullable error))reply;

/// Get statistics for a mount.
/// @param mountpoint The mountpoint to get stats for
/// @param reply Completion handler with stats dictionary
- (void)getStatsWithMountpoint:(NSString *)mountpoint
                         reply:(void (^)(NSDictionary<NSString *, id> * _Nullable stats, NSError * _Nullable error))reply;

/// Ping the service to check if it's alive.
/// @param reply Completion handler with alive status
- (void)pingWithReply:(void (^)(BOOL alive))reply;

@end

// C functions for Rust interop - creates properly-typed blocks for XPC calls
#ifdef __cplusplus
extern "C" {
#endif

/// Returns the OxVaultServiceProtocol. This must be called from Rust to force
/// the linker to include the protocol symbols.
Protocol * _Nullable OxVaultServiceProtocol_get(void);

/// Callback types for XPC results
typedef void (*MountCallback)(const char * _Nullable mountpoint, int64_t error_code, const char * _Nullable error_msg, void * _Nullable context);
typedef void (*UnmountCallback)(int64_t error_code, const char * _Nullable error_msg, void * _Nullable context);
typedef void (*PingCallback)(bool alive, void * _Nullable context);

/// Call mountWithVaultPath:password:reply: on an XPC proxy with proper block encoding.
/// The callback will be called with the result.
void OxVaultXPC_mount(id _Nonnull proxy, const char * _Nonnull vault_path, const char * _Nonnull password, MountCallback _Nonnull callback, void * _Nullable context);

/// Call unmountWithMountpoint:reply: on an XPC proxy with proper block encoding.
void OxVaultXPC_unmount(id _Nonnull proxy, const char * _Nonnull mountpoint, UnmountCallback _Nonnull callback, void * _Nullable context);

/// Call pingWithReply: on an XPC proxy with proper block encoding.
void OxVaultXPC_ping(id _Nonnull proxy, PingCallback _Nonnull callback, void * _Nullable context);

#ifdef __cplusplus
}
#endif
