import Foundation
import COxVaultFFI

public func create<GenericIntoRustString: IntoRustString>(_ vault_path: GenericIntoRustString, _ password: GenericIntoRustString) -> FsResultFs {
    FsResultFs(ptr: __swift_bridge__$crypto_fs_new({ let rustString = vault_path.intoRustString(); rustString.isOwned = false; return rustString.ptr }(), { let rustString = password.intoRustString(); rustString.isOwned = false; return rustString.ptr }()))
}

public class CryptoFilesystem: CryptoFilesystemRefMut {
    var isOwned: Bool = true

    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }

    deinit {
        if isOwned {
            __swift_bridge__$CryptoFilesystem$_free(ptr)
        }
    }
}
public class CryptoFilesystemRefMut: CryptoFilesystemRef {
    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }
}
extension CryptoFilesystemRefMut {
    public func shutdown() {
        __swift_bridge__$CryptoFilesystem$shutdown(ptr)
    }
}
public class CryptoFilesystemRef {
    var ptr: UnsafeMutableRawPointer

    public init(ptr: UnsafeMutableRawPointer) {
        self.ptr = ptr
    }
}
extension CryptoFilesystemRef {
    public func get_root_item_id() -> UInt64 {
        __swift_bridge__$CryptoFilesystem$get_root_item_id(ptr)
    }

    public func getVolumeStats() -> FsResultStats {
        FsResultStats(ptr: __swift_bridge__$CryptoFilesystem$get_volume_stats(ptr))
    }

    public func lookup<GenericIntoRustString: IntoRustString>(_ parent_id: UInt64, _ name: GenericIntoRustString) -> FsResultAttrs {
        FsResultAttrs(ptr: __swift_bridge__$CryptoFilesystem$lookup(ptr, parent_id, { let rustString = name.intoRustString(); rustString.isOwned = false; return rustString.ptr }()))
    }

    public func getAttributes(_ item_id: UInt64) -> FsResultAttrs {
        FsResultAttrs(ptr: __swift_bridge__$CryptoFilesystem$get_attributes(ptr, item_id))
    }

    public func enumerateDirectory(_ item_id: UInt64, _ cookie: UInt64) -> FsResultDirEntries {
        FsResultDirEntries(ptr: __swift_bridge__$CryptoFilesystem$enumerate_directory(ptr, item_id, cookie))
    }

    public func getEnumerationCookie(_ item_id: UInt64, _ cookie: UInt64) -> UInt64 {
        __swift_bridge__$CryptoFilesystem$get_enumeration_cookie(ptr, item_id, cookie)
    }

    public func openFile(_ item_id: UInt64, _ for_write: Bool) -> FsResultHandle {
        FsResultHandle(ptr: __swift_bridge__$CryptoFilesystem$open_file(ptr, item_id, for_write))
    }

    public func closeFile(_ handle: UInt64) -> FsResultUnit {
        FsResultUnit(ptr: __swift_bridge__$CryptoFilesystem$close_file(ptr, handle))
    }

    public func readFile(_ handle: UInt64, _ offset: Int64, _ length: Int64) -> FsResultBytes {
        FsResultBytes(ptr: __swift_bridge__$CryptoFilesystem$read_file(ptr, handle, offset, length))
    }

    public func writeFile(_ handle: UInt64, _ offset: Int64, _ data: RustVec<UInt8>) -> FsResultWritten {
        FsResultWritten(ptr: __swift_bridge__$CryptoFilesystem$write_file(ptr, handle, offset, { let val = data; val.isOwned = false; return val.ptr }()))
    }

    public func createFile<GenericIntoRustString: IntoRustString>(_ parent_id: UInt64, _ name: GenericIntoRustString) -> FsResultAttrs {
        FsResultAttrs(ptr: __swift_bridge__$CryptoFilesystem$create_file(ptr, parent_id, { let rustString = name.intoRustString(); rustString.isOwned = false; return rustString.ptr }()))
    }

    public func createDirectory<GenericIntoRustString: IntoRustString>(_ parent_id: UInt64, _ name: GenericIntoRustString) -> FsResultAttrs {
        FsResultAttrs(ptr: __swift_bridge__$CryptoFilesystem$create_directory(ptr, parent_id, { let rustString = name.intoRustString(); rustString.isOwned = false; return rustString.ptr }()))
    }

    public func createSymlink<GenericIntoRustString: IntoRustString>(_ parent_id: UInt64, _ name: GenericIntoRustString, _ target: GenericIntoRustString) -> FsResultAttrs {
        FsResultAttrs(ptr: __swift_bridge__$CryptoFilesystem$create_symlink(ptr, parent_id, { let rustString = name.intoRustString(); rustString.isOwned = false; return rustString.ptr }(), { let rustString = target.intoRustString(); rustString.isOwned = false; return rustString.ptr }()))
    }

    public func remove<GenericIntoRustString: IntoRustString>(_ parent_id: UInt64, _ name: GenericIntoRustString, _ item_id: UInt64) -> FsResultUnit {
        FsResultUnit(ptr: __swift_bridge__$CryptoFilesystem$remove(ptr, parent_id, { let rustString = name.intoRustString(); rustString.isOwned = false; return rustString.ptr }(), item_id))
    }

    public func rename<GenericIntoRustString: IntoRustString>(_ src_parent_id: UInt64, _ src_name: GenericIntoRustString, _ dst_parent_id: UInt64, _ dst_name: GenericIntoRustString, _ item_id: UInt64) -> FsResultUnit {
        FsResultUnit(ptr: __swift_bridge__$CryptoFilesystem$rename(ptr, src_parent_id, { let rustString = src_name.intoRustString(); rustString.isOwned = false; return rustString.ptr }(), dst_parent_id, { let rustString = dst_name.intoRustString(); rustString.isOwned = false; return rustString.ptr }(), item_id))
    }

    public func readSymlink(_ item_id: UInt64) -> FsResultBytes {
        FsResultBytes(ptr: __swift_bridge__$CryptoFilesystem$read_symlink(ptr, item_id))
    }

    public func truncate(_ item_id: UInt64, _ size: UInt64) -> FsResultUnit {
        FsResultUnit(ptr: __swift_bridge__$CryptoFilesystem$truncate(ptr, item_id, size))
    }

    public func reclaim(_ item_id: UInt64) {
        __swift_bridge__$CryptoFilesystem$reclaim(ptr, item_id)
    }
}
extension CryptoFilesystem: Vectorizable {
    public static func vecOfSelfNew() -> UnsafeMutableRawPointer {
        __swift_bridge__$Vec_CryptoFilesystem$new()
    }

    public static func vecOfSelfFree(vecPtr: UnsafeMutableRawPointer) {
        __swift_bridge__$Vec_CryptoFilesystem$drop(vecPtr)
    }

    public static func vecOfSelfPush(vecPtr: UnsafeMutableRawPointer, value: CryptoFilesystem) {
        __swift_bridge__$Vec_CryptoFilesystem$push(vecPtr, {value.isOwned = false; return value.ptr;}())
    }

    public static func vecOfSelfPop(vecPtr: UnsafeMutableRawPointer) -> Optional<Self> {
        let pointer = __swift_bridge__$Vec_CryptoFilesystem$pop(vecPtr)
        if pointer == nil {
            return nil
        } else {
            return (CryptoFilesystem(ptr: pointer!) as! Self)
        }
    }

    public static func vecOfSelfGet(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<CryptoFilesystemRef> {
        let pointer = __swift_bridge__$Vec_CryptoFilesystem$get(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return CryptoFilesystemRef(ptr: pointer!)
        }
    }

    public static func vecOfSelfGetMut(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<CryptoFilesystemRefMut> {
        let pointer = __swift_bridge__$Vec_CryptoFilesystem$get_mut(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return CryptoFilesystemRefMut(ptr: pointer!)
        }
    }

    public static func vecOfSelfAsPtr(vecPtr: UnsafeMutableRawPointer) -> UnsafePointer<CryptoFilesystemRef> {
        UnsafePointer<CryptoFilesystemRef>(OpaquePointer(__swift_bridge__$Vec_CryptoFilesystem$as_ptr(vecPtr)))
    }

    public static func vecOfSelfLen(vecPtr: UnsafeMutableRawPointer) -> UInt {
        __swift_bridge__$Vec_CryptoFilesystem$len(vecPtr)
    }
}


public class FsResultFs: FsResultFsRefMut {
    var isOwned: Bool = true

    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }

    deinit {
        if isOwned {
            __swift_bridge__$FsResultFs$_free(ptr)
        }
    }
}
extension FsResultFs {
    public func unwrap() -> CryptoFilesystem {
        CryptoFilesystem(ptr: __swift_bridge__$FsResultFs$result_fs_unwrap({isOwned = false; return ptr;}()))
    }
}
public class FsResultFsRefMut: FsResultFsRef {
    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }
}
public class FsResultFsRef {
    var ptr: UnsafeMutableRawPointer

    public init(ptr: UnsafeMutableRawPointer) {
        self.ptr = ptr
    }
}
extension FsResultFsRef {
    public func isOk() -> Bool {
        __swift_bridge__$FsResultFs$result_fs_is_ok(ptr)
    }

    public func getError() -> Int32 {
        __swift_bridge__$FsResultFs$result_fs_error(ptr)
    }
}
extension FsResultFs: Vectorizable {
    public static func vecOfSelfNew() -> UnsafeMutableRawPointer {
        __swift_bridge__$Vec_FsResultFs$new()
    }

    public static func vecOfSelfFree(vecPtr: UnsafeMutableRawPointer) {
        __swift_bridge__$Vec_FsResultFs$drop(vecPtr)
    }

    public static func vecOfSelfPush(vecPtr: UnsafeMutableRawPointer, value: FsResultFs) {
        __swift_bridge__$Vec_FsResultFs$push(vecPtr, {value.isOwned = false; return value.ptr;}())
    }

    public static func vecOfSelfPop(vecPtr: UnsafeMutableRawPointer) -> Optional<Self> {
        let pointer = __swift_bridge__$Vec_FsResultFs$pop(vecPtr)
        if pointer == nil {
            return nil
        } else {
            return (FsResultFs(ptr: pointer!) as! Self)
        }
    }

    public static func vecOfSelfGet(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<FsResultFsRef> {
        let pointer = __swift_bridge__$Vec_FsResultFs$get(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return FsResultFsRef(ptr: pointer!)
        }
    }

    public static func vecOfSelfGetMut(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<FsResultFsRefMut> {
        let pointer = __swift_bridge__$Vec_FsResultFs$get_mut(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return FsResultFsRefMut(ptr: pointer!)
        }
    }

    public static func vecOfSelfAsPtr(vecPtr: UnsafeMutableRawPointer) -> UnsafePointer<FsResultFsRef> {
        UnsafePointer<FsResultFsRef>(OpaquePointer(__swift_bridge__$Vec_FsResultFs$as_ptr(vecPtr)))
    }

    public static func vecOfSelfLen(vecPtr: UnsafeMutableRawPointer) -> UInt {
        __swift_bridge__$Vec_FsResultFs$len(vecPtr)
    }
}


public class FsResultAttrs: FsResultAttrsRefMut {
    var isOwned: Bool = true

    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }

    deinit {
        if isOwned {
            __swift_bridge__$FsResultAttrs$_free(ptr)
        }
    }
}
extension FsResultAttrs {
    public func unwrap() -> FileAttributes {
        FileAttributes(ptr: __swift_bridge__$FsResultAttrs$result_attrs_unwrap({isOwned = false; return ptr;}()))
    }
}
public class FsResultAttrsRefMut: FsResultAttrsRef {
    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }
}
public class FsResultAttrsRef {
    var ptr: UnsafeMutableRawPointer

    public init(ptr: UnsafeMutableRawPointer) {
        self.ptr = ptr
    }
}
extension FsResultAttrsRef {
    public func isOk() -> Bool {
        __swift_bridge__$FsResultAttrs$result_attrs_is_ok(ptr)
    }

    public func getError() -> Int32 {
        __swift_bridge__$FsResultAttrs$result_attrs_error(ptr)
    }
}
extension FsResultAttrs: Vectorizable {
    public static func vecOfSelfNew() -> UnsafeMutableRawPointer {
        __swift_bridge__$Vec_FsResultAttrs$new()
    }

    public static func vecOfSelfFree(vecPtr: UnsafeMutableRawPointer) {
        __swift_bridge__$Vec_FsResultAttrs$drop(vecPtr)
    }

    public static func vecOfSelfPush(vecPtr: UnsafeMutableRawPointer, value: FsResultAttrs) {
        __swift_bridge__$Vec_FsResultAttrs$push(vecPtr, {value.isOwned = false; return value.ptr;}())
    }

    public static func vecOfSelfPop(vecPtr: UnsafeMutableRawPointer) -> Optional<Self> {
        let pointer = __swift_bridge__$Vec_FsResultAttrs$pop(vecPtr)
        if pointer == nil {
            return nil
        } else {
            return (FsResultAttrs(ptr: pointer!) as! Self)
        }
    }

    public static func vecOfSelfGet(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<FsResultAttrsRef> {
        let pointer = __swift_bridge__$Vec_FsResultAttrs$get(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return FsResultAttrsRef(ptr: pointer!)
        }
    }

    public static func vecOfSelfGetMut(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<FsResultAttrsRefMut> {
        let pointer = __swift_bridge__$Vec_FsResultAttrs$get_mut(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return FsResultAttrsRefMut(ptr: pointer!)
        }
    }

    public static func vecOfSelfAsPtr(vecPtr: UnsafeMutableRawPointer) -> UnsafePointer<FsResultAttrsRef> {
        UnsafePointer<FsResultAttrsRef>(OpaquePointer(__swift_bridge__$Vec_FsResultAttrs$as_ptr(vecPtr)))
    }

    public static func vecOfSelfLen(vecPtr: UnsafeMutableRawPointer) -> UInt {
        __swift_bridge__$Vec_FsResultAttrs$len(vecPtr)
    }
}


public class FsResultStats: FsResultStatsRefMut {
    var isOwned: Bool = true

    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }

    deinit {
        if isOwned {
            __swift_bridge__$FsResultStats$_free(ptr)
        }
    }
}
extension FsResultStats {
    public func unwrap() -> VolumeStatistics {
        VolumeStatistics(ptr: __swift_bridge__$FsResultStats$result_stats_unwrap({isOwned = false; return ptr;}()))
    }
}
public class FsResultStatsRefMut: FsResultStatsRef {
    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }
}
public class FsResultStatsRef {
    var ptr: UnsafeMutableRawPointer

    public init(ptr: UnsafeMutableRawPointer) {
        self.ptr = ptr
    }
}
extension FsResultStatsRef {
    public func isOk() -> Bool {
        __swift_bridge__$FsResultStats$result_stats_is_ok(ptr)
    }

    public func getError() -> Int32 {
        __swift_bridge__$FsResultStats$result_stats_error(ptr)
    }
}
extension FsResultStats: Vectorizable {
    public static func vecOfSelfNew() -> UnsafeMutableRawPointer {
        __swift_bridge__$Vec_FsResultStats$new()
    }

    public static func vecOfSelfFree(vecPtr: UnsafeMutableRawPointer) {
        __swift_bridge__$Vec_FsResultStats$drop(vecPtr)
    }

    public static func vecOfSelfPush(vecPtr: UnsafeMutableRawPointer, value: FsResultStats) {
        __swift_bridge__$Vec_FsResultStats$push(vecPtr, {value.isOwned = false; return value.ptr;}())
    }

    public static func vecOfSelfPop(vecPtr: UnsafeMutableRawPointer) -> Optional<Self> {
        let pointer = __swift_bridge__$Vec_FsResultStats$pop(vecPtr)
        if pointer == nil {
            return nil
        } else {
            return (FsResultStats(ptr: pointer!) as! Self)
        }
    }

    public static func vecOfSelfGet(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<FsResultStatsRef> {
        let pointer = __swift_bridge__$Vec_FsResultStats$get(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return FsResultStatsRef(ptr: pointer!)
        }
    }

    public static func vecOfSelfGetMut(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<FsResultStatsRefMut> {
        let pointer = __swift_bridge__$Vec_FsResultStats$get_mut(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return FsResultStatsRefMut(ptr: pointer!)
        }
    }

    public static func vecOfSelfAsPtr(vecPtr: UnsafeMutableRawPointer) -> UnsafePointer<FsResultStatsRef> {
        UnsafePointer<FsResultStatsRef>(OpaquePointer(__swift_bridge__$Vec_FsResultStats$as_ptr(vecPtr)))
    }

    public static func vecOfSelfLen(vecPtr: UnsafeMutableRawPointer) -> UInt {
        __swift_bridge__$Vec_FsResultStats$len(vecPtr)
    }
}


public class FsResultDirEntries: FsResultDirEntriesRefMut {
    var isOwned: Bool = true

    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }

    deinit {
        if isOwned {
            __swift_bridge__$FsResultDirEntries$_free(ptr)
        }
    }
}
extension FsResultDirEntries {
    public func unwrap() -> RustVec<DirectoryEntry> {
        RustVec(ptr: __swift_bridge__$FsResultDirEntries$result_dir_unwrap({isOwned = false; return ptr;}()))
    }
}
public class FsResultDirEntriesRefMut: FsResultDirEntriesRef {
    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }
}
public class FsResultDirEntriesRef {
    var ptr: UnsafeMutableRawPointer

    public init(ptr: UnsafeMutableRawPointer) {
        self.ptr = ptr
    }
}
extension FsResultDirEntriesRef {
    public func isOk() -> Bool {
        __swift_bridge__$FsResultDirEntries$result_dir_is_ok(ptr)
    }

    public func getError() -> Int32 {
        __swift_bridge__$FsResultDirEntries$result_dir_error(ptr)
    }
}
extension FsResultDirEntries: Vectorizable {
    public static func vecOfSelfNew() -> UnsafeMutableRawPointer {
        __swift_bridge__$Vec_FsResultDirEntries$new()
    }

    public static func vecOfSelfFree(vecPtr: UnsafeMutableRawPointer) {
        __swift_bridge__$Vec_FsResultDirEntries$drop(vecPtr)
    }

    public static func vecOfSelfPush(vecPtr: UnsafeMutableRawPointer, value: FsResultDirEntries) {
        __swift_bridge__$Vec_FsResultDirEntries$push(vecPtr, {value.isOwned = false; return value.ptr;}())
    }

    public static func vecOfSelfPop(vecPtr: UnsafeMutableRawPointer) -> Optional<Self> {
        let pointer = __swift_bridge__$Vec_FsResultDirEntries$pop(vecPtr)
        if pointer == nil {
            return nil
        } else {
            return (FsResultDirEntries(ptr: pointer!) as! Self)
        }
    }

    public static func vecOfSelfGet(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<FsResultDirEntriesRef> {
        let pointer = __swift_bridge__$Vec_FsResultDirEntries$get(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return FsResultDirEntriesRef(ptr: pointer!)
        }
    }

    public static func vecOfSelfGetMut(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<FsResultDirEntriesRefMut> {
        let pointer = __swift_bridge__$Vec_FsResultDirEntries$get_mut(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return FsResultDirEntriesRefMut(ptr: pointer!)
        }
    }

    public static func vecOfSelfAsPtr(vecPtr: UnsafeMutableRawPointer) -> UnsafePointer<FsResultDirEntriesRef> {
        UnsafePointer<FsResultDirEntriesRef>(OpaquePointer(__swift_bridge__$Vec_FsResultDirEntries$as_ptr(vecPtr)))
    }

    public static func vecOfSelfLen(vecPtr: UnsafeMutableRawPointer) -> UInt {
        __swift_bridge__$Vec_FsResultDirEntries$len(vecPtr)
    }
}


public class FsResultHandle: FsResultHandleRefMut {
    var isOwned: Bool = true

    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }

    deinit {
        if isOwned {
            __swift_bridge__$FsResultHandle$_free(ptr)
        }
    }
}
public class FsResultHandleRefMut: FsResultHandleRef {
    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }
}
public class FsResultHandleRef {
    var ptr: UnsafeMutableRawPointer

    public init(ptr: UnsafeMutableRawPointer) {
        self.ptr = ptr
    }
}
extension FsResultHandleRef {
    public func isOk() -> Bool {
        __swift_bridge__$FsResultHandle$result_handle_is_ok(ptr)
    }

    public func getError() -> Int32 {
        __swift_bridge__$FsResultHandle$result_handle_error(ptr)
    }

    public func unwrap() -> UInt64 {
        __swift_bridge__$FsResultHandle$result_handle_unwrap(ptr)
    }
}
extension FsResultHandle: Vectorizable {
    public static func vecOfSelfNew() -> UnsafeMutableRawPointer {
        __swift_bridge__$Vec_FsResultHandle$new()
    }

    public static func vecOfSelfFree(vecPtr: UnsafeMutableRawPointer) {
        __swift_bridge__$Vec_FsResultHandle$drop(vecPtr)
    }

    public static func vecOfSelfPush(vecPtr: UnsafeMutableRawPointer, value: FsResultHandle) {
        __swift_bridge__$Vec_FsResultHandle$push(vecPtr, {value.isOwned = false; return value.ptr;}())
    }

    public static func vecOfSelfPop(vecPtr: UnsafeMutableRawPointer) -> Optional<Self> {
        let pointer = __swift_bridge__$Vec_FsResultHandle$pop(vecPtr)
        if pointer == nil {
            return nil
        } else {
            return (FsResultHandle(ptr: pointer!) as! Self)
        }
    }

    public static func vecOfSelfGet(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<FsResultHandleRef> {
        let pointer = __swift_bridge__$Vec_FsResultHandle$get(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return FsResultHandleRef(ptr: pointer!)
        }
    }

    public static func vecOfSelfGetMut(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<FsResultHandleRefMut> {
        let pointer = __swift_bridge__$Vec_FsResultHandle$get_mut(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return FsResultHandleRefMut(ptr: pointer!)
        }
    }

    public static func vecOfSelfAsPtr(vecPtr: UnsafeMutableRawPointer) -> UnsafePointer<FsResultHandleRef> {
        UnsafePointer<FsResultHandleRef>(OpaquePointer(__swift_bridge__$Vec_FsResultHandle$as_ptr(vecPtr)))
    }

    public static func vecOfSelfLen(vecPtr: UnsafeMutableRawPointer) -> UInt {
        __swift_bridge__$Vec_FsResultHandle$len(vecPtr)
    }
}


public class FsResultUnit: FsResultUnitRefMut {
    var isOwned: Bool = true

    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }

    deinit {
        if isOwned {
            __swift_bridge__$FsResultUnit$_free(ptr)
        }
    }
}
public class FsResultUnitRefMut: FsResultUnitRef {
    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }
}
public class FsResultUnitRef {
    var ptr: UnsafeMutableRawPointer

    public init(ptr: UnsafeMutableRawPointer) {
        self.ptr = ptr
    }
}
extension FsResultUnitRef {
    public func isOk() -> Bool {
        __swift_bridge__$FsResultUnit$result_unit_is_ok(ptr)
    }

    public func getError() -> Int32 {
        __swift_bridge__$FsResultUnit$result_unit_error(ptr)
    }
}
extension FsResultUnit: Vectorizable {
    public static func vecOfSelfNew() -> UnsafeMutableRawPointer {
        __swift_bridge__$Vec_FsResultUnit$new()
    }

    public static func vecOfSelfFree(vecPtr: UnsafeMutableRawPointer) {
        __swift_bridge__$Vec_FsResultUnit$drop(vecPtr)
    }

    public static func vecOfSelfPush(vecPtr: UnsafeMutableRawPointer, value: FsResultUnit) {
        __swift_bridge__$Vec_FsResultUnit$push(vecPtr, {value.isOwned = false; return value.ptr;}())
    }

    public static func vecOfSelfPop(vecPtr: UnsafeMutableRawPointer) -> Optional<Self> {
        let pointer = __swift_bridge__$Vec_FsResultUnit$pop(vecPtr)
        if pointer == nil {
            return nil
        } else {
            return (FsResultUnit(ptr: pointer!) as! Self)
        }
    }

    public static func vecOfSelfGet(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<FsResultUnitRef> {
        let pointer = __swift_bridge__$Vec_FsResultUnit$get(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return FsResultUnitRef(ptr: pointer!)
        }
    }

    public static func vecOfSelfGetMut(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<FsResultUnitRefMut> {
        let pointer = __swift_bridge__$Vec_FsResultUnit$get_mut(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return FsResultUnitRefMut(ptr: pointer!)
        }
    }

    public static func vecOfSelfAsPtr(vecPtr: UnsafeMutableRawPointer) -> UnsafePointer<FsResultUnitRef> {
        UnsafePointer<FsResultUnitRef>(OpaquePointer(__swift_bridge__$Vec_FsResultUnit$as_ptr(vecPtr)))
    }

    public static func vecOfSelfLen(vecPtr: UnsafeMutableRawPointer) -> UInt {
        __swift_bridge__$Vec_FsResultUnit$len(vecPtr)
    }
}


public class FsResultBytes: FsResultBytesRefMut {
    var isOwned: Bool = true

    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }

    deinit {
        if isOwned {
            __swift_bridge__$FsResultBytes$_free(ptr)
        }
    }
}
extension FsResultBytes {
    public func unwrap() -> RustVec<UInt8> {
        RustVec(ptr: __swift_bridge__$FsResultBytes$result_bytes_unwrap({isOwned = false; return ptr;}()))
    }
}
public class FsResultBytesRefMut: FsResultBytesRef {
    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }
}
public class FsResultBytesRef {
    var ptr: UnsafeMutableRawPointer

    public init(ptr: UnsafeMutableRawPointer) {
        self.ptr = ptr
    }
}
extension FsResultBytesRef {
    public func isOk() -> Bool {
        __swift_bridge__$FsResultBytes$result_bytes_is_ok(ptr)
    }

    public func getError() -> Int32 {
        __swift_bridge__$FsResultBytes$result_bytes_error(ptr)
    }
}
extension FsResultBytes: Vectorizable {
    public static func vecOfSelfNew() -> UnsafeMutableRawPointer {
        __swift_bridge__$Vec_FsResultBytes$new()
    }

    public static func vecOfSelfFree(vecPtr: UnsafeMutableRawPointer) {
        __swift_bridge__$Vec_FsResultBytes$drop(vecPtr)
    }

    public static func vecOfSelfPush(vecPtr: UnsafeMutableRawPointer, value: FsResultBytes) {
        __swift_bridge__$Vec_FsResultBytes$push(vecPtr, {value.isOwned = false; return value.ptr;}())
    }

    public static func vecOfSelfPop(vecPtr: UnsafeMutableRawPointer) -> Optional<Self> {
        let pointer = __swift_bridge__$Vec_FsResultBytes$pop(vecPtr)
        if pointer == nil {
            return nil
        } else {
            return (FsResultBytes(ptr: pointer!) as! Self)
        }
    }

    public static func vecOfSelfGet(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<FsResultBytesRef> {
        let pointer = __swift_bridge__$Vec_FsResultBytes$get(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return FsResultBytesRef(ptr: pointer!)
        }
    }

    public static func vecOfSelfGetMut(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<FsResultBytesRefMut> {
        let pointer = __swift_bridge__$Vec_FsResultBytes$get_mut(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return FsResultBytesRefMut(ptr: pointer!)
        }
    }

    public static func vecOfSelfAsPtr(vecPtr: UnsafeMutableRawPointer) -> UnsafePointer<FsResultBytesRef> {
        UnsafePointer<FsResultBytesRef>(OpaquePointer(__swift_bridge__$Vec_FsResultBytes$as_ptr(vecPtr)))
    }

    public static func vecOfSelfLen(vecPtr: UnsafeMutableRawPointer) -> UInt {
        __swift_bridge__$Vec_FsResultBytes$len(vecPtr)
    }
}


public class FsResultWritten: FsResultWrittenRefMut {
    var isOwned: Bool = true

    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }

    deinit {
        if isOwned {
            __swift_bridge__$FsResultWritten$_free(ptr)
        }
    }
}
public class FsResultWrittenRefMut: FsResultWrittenRef {
    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }
}
public class FsResultWrittenRef {
    var ptr: UnsafeMutableRawPointer

    public init(ptr: UnsafeMutableRawPointer) {
        self.ptr = ptr
    }
}
extension FsResultWrittenRef {
    public func isOk() -> Bool {
        __swift_bridge__$FsResultWritten$result_written_is_ok(ptr)
    }

    public func getError() -> Int32 {
        __swift_bridge__$FsResultWritten$result_written_error(ptr)
    }

    public func unwrap() -> Int64 {
        __swift_bridge__$FsResultWritten$result_written_unwrap(ptr)
    }
}
extension FsResultWritten: Vectorizable {
    public static func vecOfSelfNew() -> UnsafeMutableRawPointer {
        __swift_bridge__$Vec_FsResultWritten$new()
    }

    public static func vecOfSelfFree(vecPtr: UnsafeMutableRawPointer) {
        __swift_bridge__$Vec_FsResultWritten$drop(vecPtr)
    }

    public static func vecOfSelfPush(vecPtr: UnsafeMutableRawPointer, value: FsResultWritten) {
        __swift_bridge__$Vec_FsResultWritten$push(vecPtr, {value.isOwned = false; return value.ptr;}())
    }

    public static func vecOfSelfPop(vecPtr: UnsafeMutableRawPointer) -> Optional<Self> {
        let pointer = __swift_bridge__$Vec_FsResultWritten$pop(vecPtr)
        if pointer == nil {
            return nil
        } else {
            return (FsResultWritten(ptr: pointer!) as! Self)
        }
    }

    public static func vecOfSelfGet(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<FsResultWrittenRef> {
        let pointer = __swift_bridge__$Vec_FsResultWritten$get(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return FsResultWrittenRef(ptr: pointer!)
        }
    }

    public static func vecOfSelfGetMut(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<FsResultWrittenRefMut> {
        let pointer = __swift_bridge__$Vec_FsResultWritten$get_mut(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return FsResultWrittenRefMut(ptr: pointer!)
        }
    }

    public static func vecOfSelfAsPtr(vecPtr: UnsafeMutableRawPointer) -> UnsafePointer<FsResultWrittenRef> {
        UnsafePointer<FsResultWrittenRef>(OpaquePointer(__swift_bridge__$Vec_FsResultWritten$as_ptr(vecPtr)))
    }

    public static func vecOfSelfLen(vecPtr: UnsafeMutableRawPointer) -> UInt {
        __swift_bridge__$Vec_FsResultWritten$len(vecPtr)
    }
}


public class FileAttributes: FileAttributesRefMut {
    var isOwned: Bool = true

    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }

    deinit {
        if isOwned {
            __swift_bridge__$FileAttributes$_free(ptr)
        }
    }
}
public class FileAttributesRefMut: FileAttributesRef {
    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }
}
public class FileAttributesRef {
    var ptr: UnsafeMutableRawPointer

    public init(ptr: UnsafeMutableRawPointer) {
        self.ptr = ptr
    }
}
extension FileAttributesRef {
    public func getItemId() -> UInt64 {
        __swift_bridge__$FileAttributes$attr_item_id(ptr)
    }

    public func isDirectory() -> Bool {
        __swift_bridge__$FileAttributes$attr_is_directory(ptr)
    }

    public func isFile() -> Bool {
        __swift_bridge__$FileAttributes$attr_is_file(ptr)
    }

    public func isSymlink() -> Bool {
        __swift_bridge__$FileAttributes$attr_is_symlink(ptr)
    }

    public func getSize() -> UInt64 {
        __swift_bridge__$FileAttributes$attr_size(ptr)
    }

    public func getMode() -> UInt32 {
        __swift_bridge__$FileAttributes$attr_mode(ptr)
    }

    public func getUid() -> UInt32 {
        __swift_bridge__$FileAttributes$attr_uid(ptr)
    }

    public func getGid() -> UInt32 {
        __swift_bridge__$FileAttributes$attr_gid(ptr)
    }
}
extension FileAttributes: Vectorizable {
    public static func vecOfSelfNew() -> UnsafeMutableRawPointer {
        __swift_bridge__$Vec_FileAttributes$new()
    }

    public static func vecOfSelfFree(vecPtr: UnsafeMutableRawPointer) {
        __swift_bridge__$Vec_FileAttributes$drop(vecPtr)
    }

    public static func vecOfSelfPush(vecPtr: UnsafeMutableRawPointer, value: FileAttributes) {
        __swift_bridge__$Vec_FileAttributes$push(vecPtr, {value.isOwned = false; return value.ptr;}())
    }

    public static func vecOfSelfPop(vecPtr: UnsafeMutableRawPointer) -> Optional<Self> {
        let pointer = __swift_bridge__$Vec_FileAttributes$pop(vecPtr)
        if pointer == nil {
            return nil
        } else {
            return (FileAttributes(ptr: pointer!) as! Self)
        }
    }

    public static func vecOfSelfGet(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<FileAttributesRef> {
        let pointer = __swift_bridge__$Vec_FileAttributes$get(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return FileAttributesRef(ptr: pointer!)
        }
    }

    public static func vecOfSelfGetMut(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<FileAttributesRefMut> {
        let pointer = __swift_bridge__$Vec_FileAttributes$get_mut(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return FileAttributesRefMut(ptr: pointer!)
        }
    }

    public static func vecOfSelfAsPtr(vecPtr: UnsafeMutableRawPointer) -> UnsafePointer<FileAttributesRef> {
        UnsafePointer<FileAttributesRef>(OpaquePointer(__swift_bridge__$Vec_FileAttributes$as_ptr(vecPtr)))
    }

    public static func vecOfSelfLen(vecPtr: UnsafeMutableRawPointer) -> UInt {
        __swift_bridge__$Vec_FileAttributes$len(vecPtr)
    }
}


public class DirectoryEntry: DirectoryEntryRefMut {
    var isOwned: Bool = true

    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }

    deinit {
        if isOwned {
            __swift_bridge__$DirectoryEntry$_free(ptr)
        }
    }
}
public class DirectoryEntryRefMut: DirectoryEntryRef {
    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }
}
public class DirectoryEntryRef {
    var ptr: UnsafeMutableRawPointer

    public init(ptr: UnsafeMutableRawPointer) {
        self.ptr = ptr
    }
}
extension DirectoryEntryRef {
    public func getName() -> RustVec<UInt8> {
        RustVec(ptr: __swift_bridge__$DirectoryEntry$entry_name(ptr))
    }

    public func getItemId() -> UInt64 {
        __swift_bridge__$DirectoryEntry$entry_item_id(ptr)
    }

    public func isDirectory() -> Bool {
        __swift_bridge__$DirectoryEntry$entry_is_directory(ptr)
    }

    public func isFile() -> Bool {
        __swift_bridge__$DirectoryEntry$entry_is_file(ptr)
    }

    public func isSymlink() -> Bool {
        __swift_bridge__$DirectoryEntry$entry_is_symlink(ptr)
    }

    public func getSize() -> UInt64 {
        __swift_bridge__$DirectoryEntry$entry_size(ptr)
    }
}
extension DirectoryEntry: Vectorizable {
    public static func vecOfSelfNew() -> UnsafeMutableRawPointer {
        __swift_bridge__$Vec_DirectoryEntry$new()
    }

    public static func vecOfSelfFree(vecPtr: UnsafeMutableRawPointer) {
        __swift_bridge__$Vec_DirectoryEntry$drop(vecPtr)
    }

    public static func vecOfSelfPush(vecPtr: UnsafeMutableRawPointer, value: DirectoryEntry) {
        __swift_bridge__$Vec_DirectoryEntry$push(vecPtr, {value.isOwned = false; return value.ptr;}())
    }

    public static func vecOfSelfPop(vecPtr: UnsafeMutableRawPointer) -> Optional<Self> {
        let pointer = __swift_bridge__$Vec_DirectoryEntry$pop(vecPtr)
        if pointer == nil {
            return nil
        } else {
            return (DirectoryEntry(ptr: pointer!) as! Self)
        }
    }

    public static func vecOfSelfGet(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<DirectoryEntryRef> {
        let pointer = __swift_bridge__$Vec_DirectoryEntry$get(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return DirectoryEntryRef(ptr: pointer!)
        }
    }

    public static func vecOfSelfGetMut(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<DirectoryEntryRefMut> {
        let pointer = __swift_bridge__$Vec_DirectoryEntry$get_mut(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return DirectoryEntryRefMut(ptr: pointer!)
        }
    }

    public static func vecOfSelfAsPtr(vecPtr: UnsafeMutableRawPointer) -> UnsafePointer<DirectoryEntryRef> {
        UnsafePointer<DirectoryEntryRef>(OpaquePointer(__swift_bridge__$Vec_DirectoryEntry$as_ptr(vecPtr)))
    }

    public static func vecOfSelfLen(vecPtr: UnsafeMutableRawPointer) -> UInt {
        __swift_bridge__$Vec_DirectoryEntry$len(vecPtr)
    }
}


public class VolumeStatistics: VolumeStatisticsRefMut {
    var isOwned: Bool = true

    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }

    deinit {
        if isOwned {
            __swift_bridge__$VolumeStatistics$_free(ptr)
        }
    }
}
public class VolumeStatisticsRefMut: VolumeStatisticsRef {
    public override init(ptr: UnsafeMutableRawPointer) {
        super.init(ptr: ptr)
    }
}
public class VolumeStatisticsRef {
    var ptr: UnsafeMutableRawPointer

    public init(ptr: UnsafeMutableRawPointer) {
        self.ptr = ptr
    }
}
extension VolumeStatisticsRef {
    public func getTotalBytes() -> UInt64 {
        __swift_bridge__$VolumeStatistics$stats_total_bytes(ptr)
    }

    public func getAvailableBytes() -> UInt64 {
        __swift_bridge__$VolumeStatistics$stats_available_bytes(ptr)
    }

    public func getUsedBytes() -> UInt64 {
        __swift_bridge__$VolumeStatistics$stats_used_bytes(ptr)
    }

    public func getTotalInodes() -> UInt64 {
        __swift_bridge__$VolumeStatistics$stats_total_inodes(ptr)
    }

    public func getAvailableInodes() -> UInt64 {
        __swift_bridge__$VolumeStatistics$stats_available_inodes(ptr)
    }

    public func getBlockSize() -> UInt32 {
        __swift_bridge__$VolumeStatistics$stats_block_size(ptr)
    }
}
extension VolumeStatistics: Vectorizable {
    public static func vecOfSelfNew() -> UnsafeMutableRawPointer {
        __swift_bridge__$Vec_VolumeStatistics$new()
    }

    public static func vecOfSelfFree(vecPtr: UnsafeMutableRawPointer) {
        __swift_bridge__$Vec_VolumeStatistics$drop(vecPtr)
    }

    public static func vecOfSelfPush(vecPtr: UnsafeMutableRawPointer, value: VolumeStatistics) {
        __swift_bridge__$Vec_VolumeStatistics$push(vecPtr, {value.isOwned = false; return value.ptr;}())
    }

    public static func vecOfSelfPop(vecPtr: UnsafeMutableRawPointer) -> Optional<Self> {
        let pointer = __swift_bridge__$Vec_VolumeStatistics$pop(vecPtr)
        if pointer == nil {
            return nil
        } else {
            return (VolumeStatistics(ptr: pointer!) as! Self)
        }
    }

    public static func vecOfSelfGet(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<VolumeStatisticsRef> {
        let pointer = __swift_bridge__$Vec_VolumeStatistics$get(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return VolumeStatisticsRef(ptr: pointer!)
        }
    }

    public static func vecOfSelfGetMut(vecPtr: UnsafeMutableRawPointer, index: UInt) -> Optional<VolumeStatisticsRefMut> {
        let pointer = __swift_bridge__$Vec_VolumeStatistics$get_mut(vecPtr, index)
        if pointer == nil {
            return nil
        } else {
            return VolumeStatisticsRefMut(ptr: pointer!)
        }
    }

    public static func vecOfSelfAsPtr(vecPtr: UnsafeMutableRawPointer) -> UnsafePointer<VolumeStatisticsRef> {
        UnsafePointer<VolumeStatisticsRef>(OpaquePointer(__swift_bridge__$Vec_VolumeStatistics$as_ptr(vecPtr)))
    }

    public static func vecOfSelfLen(vecPtr: UnsafeMutableRawPointer) -> UInt {
        __swift_bridge__$Vec_VolumeStatistics$len(vecPtr)
    }
}
