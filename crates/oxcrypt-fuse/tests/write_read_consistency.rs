//! Test write-read consistency immediately after mount.
//!
//! This test reproduces the git workload issue where files created in iteration 0
//! (immediately after mount) cannot be read back, but subsequent iterations work fine.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

/// Helper to mount vault and return mount point
fn mount_test_vault() -> (PathBuf, impl Drop) {
    use oxcrypt_fuse::FuseBackend;
    use oxcrypt_mount::MountBackend;

    let vault_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test_vault");

    let mount_point = PathBuf::from("/tmp/fuse_consistency_test");
    fs::create_dir_all(&mount_point).unwrap();

    let backend = FuseBackend::new();
    let handle = backend
        .mount(
            "consistency_test",
            &vault_path,
            "123456789",
            &mount_point,
        )
        .expect("Failed to mount");

    // Brief delay to let mount settle
    thread::sleep(Duration::from_millis(100));

    (mount_point, handle)
}

#[test]
fn test_immediate_write_read() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let (mount_point, _handle) = mount_test_vault();

    // Create a test file
    let test_file = mount_point.join("immediate_test.txt");
    let test_data = b"Hello, World!";

    eprintln!("Creating and writing file: {:?}", test_file);
    {
        let mut file = File::create(&test_file).expect("Failed to create file");
        file.write_all(test_data).expect("Failed to write data");
        file.flush().expect("Failed to flush");
    } // File is closed here

    eprintln!("Reading back file: {:?}", test_file);
    // Immediately try to read it back
    let mut read_data = Vec::new();
    {
        let mut file = File::open(&test_file).expect("Failed to open file for reading");
        file.read_to_end(&mut read_data).expect("Failed to read data");
    }

    assert_eq!(
        read_data, test_data,
        "Read data doesn't match written data"
    );
}

#[test]
fn test_git_like_object_creation() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let (mount_point, _handle) = mount_test_vault();

    // Simulate git object database structure
    let objects_dir = mount_point.join(".git").join("objects").join("ab");
    fs::create_dir_all(&objects_dir).expect("Failed to create objects directory");

    // Create multiple object files (like git does)
    for i in 0..10 {
        let object_id = format!("cdef{:036x}", i);
        let object_file = objects_dir.join(&object_id);
        let object_data = format!("blob {}\0This is object {}", i, i);

        eprintln!("Creating object file: {:?}", object_file);
        {
            let mut file = File::create(&object_file).expect("Failed to create object");
            file.write_all(object_data.as_bytes())
                .expect("Failed to write object");
            file.flush().expect("Failed to flush object");
        }

        // Verify file exists in directory listing
        eprintln!("Checking directory listing for: {:?}", object_id);
        let entries: Vec<_> = fs::read_dir(&objects_dir)
            .expect("Failed to read objects dir")
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();

        assert!(
            entries.contains(&object_id),
            "Object {} not found in directory listing. Found: {:?}",
            object_id,
            entries
        );

        // Immediately try to open and read it (like git does)
        eprintln!("Reading back object: {:?}", object_file);
        let mut read_data = Vec::new();
        {
            let mut file = File::open(&object_file)
                .unwrap_or_else(|e| panic!("Failed to open object {}: {}", object_id, e));
            file.read_to_end(&mut read_data).expect("Failed to read object");
        }

        assert_eq!(
            String::from_utf8(read_data).unwrap(),
            object_data,
            "Object {} data mismatch",
            object_id
        );
    }
}

#[test]
fn test_multiple_mounts_iterations() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    // Test 3 mount/unmount cycles to see if iteration 0 is different
    for iteration in 0..3 {
        eprintln!("\n=== ITERATION {} ===", iteration);

        let (mount_point, handle) = mount_test_vault();

        let test_file = mount_point.join(format!("iter{}_test.txt", iteration));
        let test_data = format!("Iteration {}", iteration);

        eprintln!("Creating file: {:?}", test_file);
        {
            let mut file = File::create(&test_file).expect("Failed to create file");
            file.write_all(test_data.as_bytes())
                .expect("Failed to write data");
            file.flush().expect("Failed to flush");
        }

        eprintln!("Reading back file: {:?}", test_file);
        let mut read_data = String::new();
        {
            let mut file = File::open(&test_file)
                .unwrap_or_else(|e| {
                    panic!("Iteration {}: Failed to open file: {}", iteration, e)
                });
            file.read_to_string(&mut read_data).expect("Failed to read data");
        }

        assert_eq!(
            read_data, test_data,
            "Iteration {}: Data mismatch",
            iteration
        );

        // Unmount
        drop(handle);
        thread::sleep(Duration::from_millis(200));
    }
}
