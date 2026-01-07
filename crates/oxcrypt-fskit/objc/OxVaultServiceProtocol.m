// OxVaultServiceProtocol.m
// Implementation file to register the protocol with the Objective-C runtime.
// This ensures objc_getProtocol("OxVaultServiceProtocol") works in the Rust CLI.

#import "OxVaultServiceProtocol.h"

// Dummy class that conforms to the protocol.
// This FORCES the protocol to be emitted to the binary and registered
// with the Objective-C runtime. Without a conforming class, the protocol
// may be stripped by the linker.
@interface _OxVaultServiceProtocolForcer : NSObject <OxVaultServiceProtocol>
@end

@implementation _OxVaultServiceProtocolForcer

- (void)mountWithVaultPath:(NSString *)vaultPath
                  password:(NSString *)password
                     reply:(void (^)(NSString * _Nullable, NSError * _Nullable))reply {
    // Never called - just forces protocol registration
}

- (void)unmountWithMountpoint:(NSString *)mountpoint
                        reply:(void (^)(NSError * _Nullable))reply {
}

- (void)listMountsWithReply:(void (^)(NSArray<NSDictionary<NSString *, id> *> * _Nullable, NSError * _Nullable))reply {
}

- (void)getStatsWithMountpoint:(NSString *)mountpoint
                         reply:(void (^)(NSDictionary<NSString *, id> * _Nullable, NSError * _Nullable))reply {
}

- (void)pingWithReply:(void (^)(BOOL))reply {
}

@end

// Force the class to be referenced at load time
__attribute__((constructor))
static void registerProtocol(void) {
    // Reference the class to prevent it from being stripped
    (void)[_OxVaultServiceProtocolForcer class];
}

// C function to get the protocol - called from Rust to force linker to include symbols
Protocol * _Nullable OxVaultServiceProtocol_get(void) {
    // Force reference the class to ensure it's not stripped
    (void)[_OxVaultServiceProtocolForcer class];
    return @protocol(OxVaultServiceProtocol);
}

// XPC wrapper functions - create properly-typed blocks for XPC calls

void OxVaultXPC_mount(id proxy, const char *vault_path, const char *password, MountCallback callback, void *context) {
    NSString *vaultPathStr = [NSString stringWithUTF8String:vault_path];
    NSString *passwordStr = [NSString stringWithUTF8String:password];

    [(id<OxVaultServiceProtocol>)proxy mountWithVaultPath:vaultPathStr
                                                 password:passwordStr
                                                    reply:^(NSString * _Nullable mountpoint, NSError * _Nullable error) {
        if (error) {
            const char *errMsg = [[error localizedDescription] UTF8String];
            callback(NULL, [error code], errMsg, context);
        } else if (mountpoint) {
            callback([mountpoint UTF8String], 0, NULL, context);
        } else {
            callback(NULL, -1, "No mountpoint returned", context);
        }
    }];
}

void OxVaultXPC_unmount(id proxy, const char *mountpoint, UnmountCallback callback, void *context) {
    NSString *mountpointStr = [NSString stringWithUTF8String:mountpoint];

    [(id<OxVaultServiceProtocol>)proxy unmountWithMountpoint:mountpointStr
                                                       reply:^(NSError * _Nullable error) {
        if (error) {
            const char *errMsg = [[error localizedDescription] UTF8String];
            callback([error code], errMsg, context);
        } else {
            callback(0, NULL, context);
        }
    }];
}

void OxVaultXPC_ping(id proxy, PingCallback callback, void *context) {
    [(id<OxVaultServiceProtocol>)proxy pingWithReply:^(BOOL alive) {
        callback(alive ? true : false, context);
    }];
}
