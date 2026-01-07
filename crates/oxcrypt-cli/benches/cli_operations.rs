use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "bench-password-123";

/// Get the path to the oxcrypt binary
fn oxcrypt_bin() -> PathBuf {
    // Find the release binary for more realistic benchmarks
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Remove current binary name
    path.pop(); // Remove deps
    path.pop(); // Remove debug/release
    path.push("release");
    path.push("oxcrypt");

    // Fall back to debug if release doesn't exist
    if !path.exists() {
        path.pop();
        path.pop();
        path.push("debug");
        path.push("oxcrypt");
    }

    path
}

/// Create a fresh vault for benchmarking
fn create_bench_vault() -> (TempDir, PathBuf) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().join("vault");

    let status = Command::new(oxcrypt_bin())
        .arg("init")
        .arg(&vault_path)
        .arg("--password")
        .arg(TEST_PASSWORD)
        .status()
        .expect("Failed to create vault");

    assert!(status.success(), "Vault creation failed");

    (temp_dir, vault_path)
}

/// Run oxcrypt command and return success status
fn run_oxcrypt(vault_path: &PathBuf, args: &[&str]) -> bool {
    Command::new(oxcrypt_bin())
        .env("OXCRYPT_PASSWORD", TEST_PASSWORD)
        .arg("--vault")
        .arg(vault_path)
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run oxcrypt command with stdin and return output
fn run_oxcrypt_with_stdin(vault_path: &PathBuf, args: &[&str], stdin: &[u8]) -> Vec<u8> {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new(oxcrypt_bin())
        .env("OXCRYPT_PASSWORD", TEST_PASSWORD)
        .arg("--vault")
        .arg(vault_path)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn oxcrypt");

    if let Some(mut stdin_pipe) = child.stdin.take() {
        stdin_pipe.write_all(stdin).ok();
    }

    let output = child.wait_with_output().expect("Failed to wait for output");
    output.stdout
}

fn bench_init(c: &mut Criterion) {
    c.bench_function("init_vault", |b| {
        b.iter_with_setup(
            || {
                let temp_dir = TempDir::new().expect("Failed to create temp dir");
                let vault_path = temp_dir.path().join("vault");
                (temp_dir, vault_path)
            },
            |(_temp_dir, vault_path)| {
                let status = Command::new(oxcrypt_bin())
                    .arg("init")
                    .arg(&vault_path)
                    .arg("--password")
                    .arg(TEST_PASSWORD)
                    .status()
                    .expect("Failed to run init");
                black_box(status.success());
            },
        );
    });
}

fn bench_ls(c: &mut Criterion) {
    let (_temp_dir, vault_path) = create_bench_vault();

    // Create some files for a non-empty listing
    for i in 0..10 {
        run_oxcrypt_with_stdin(&vault_path, &["write", &format!("/file{i}.txt")], b"content");
    }

    c.bench_function("ls_root", |b| {
        b.iter(|| {
            let success = run_oxcrypt(&vault_path, &["ls"]);
            black_box(success);
        });
    });
}

fn bench_cat(c: &mut Criterion) {
    let mut group = c.benchmark_group("cat");
    let (_temp_dir, vault_path) = create_bench_vault();

    // Create files of different sizes
    let small_content = vec![b'a'; 1024]; // 1KB
    let medium_content = vec![b'b'; 100 * 1024]; // 100KB
    let large_content = vec![b'c'; 1024 * 1024]; // 1MB

    run_oxcrypt_with_stdin(&vault_path, &["write", "/small.txt"], &small_content);
    run_oxcrypt_with_stdin(&vault_path, &["write", "/medium.txt"], &medium_content);
    run_oxcrypt_with_stdin(&vault_path, &["write", "/large.txt"], &large_content);

    group.bench_function("1KB", |b| {
        b.iter(|| {
            let output = Command::new(oxcrypt_bin())
                .env("OXCRYPT_PASSWORD", TEST_PASSWORD)
                .arg("--vault")
                .arg(&vault_path)
                .arg("cat")
                .arg("/small.txt")
                .output()
                .expect("Failed to run cat");
            black_box(output.stdout);
        });
    });

    group.bench_function("100KB", |b| {
        b.iter(|| {
            let output = Command::new(oxcrypt_bin())
                .env("OXCRYPT_PASSWORD", TEST_PASSWORD)
                .arg("--vault")
                .arg(&vault_path)
                .arg("cat")
                .arg("/medium.txt")
                .output()
                .expect("Failed to run cat");
            black_box(output.stdout);
        });
    });

    group.bench_function("1MB", |b| {
        b.iter(|| {
            let output = Command::new(oxcrypt_bin())
                .env("OXCRYPT_PASSWORD", TEST_PASSWORD)
                .arg("--vault")
                .arg(&vault_path)
                .arg("cat")
                .arg("/large.txt")
                .output()
                .expect("Failed to run cat");
            black_box(output.stdout);
        });
    });

    group.finish();
}

fn bench_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("write");
    let (_temp_dir, vault_path) = create_bench_vault();

    let small_content = vec![b'a'; 1024]; // 1KB
    let medium_content = vec![b'b'; 100 * 1024]; // 100KB
    let large_content = vec![b'c'; 1024 * 1024]; // 1MB

    let mut counter = 0u64;

    group.bench_function("1KB", |b| {
        b.iter(|| {
            counter += 1;
            run_oxcrypt_with_stdin(
                &vault_path,
                &["write", &format!("/bench_small_{counter}.txt")],
                &small_content,
            );
        });
    });

    group.bench_function("100KB", |b| {
        b.iter(|| {
            counter += 1;
            run_oxcrypt_with_stdin(
                &vault_path,
                &["write", &format!("/bench_medium_{counter}.txt")],
                &medium_content,
            );
        });
    });

    group.bench_function("1MB", |b| {
        b.iter(|| {
            counter += 1;
            run_oxcrypt_with_stdin(
                &vault_path,
                &["write", &format!("/bench_large_{counter}.txt")],
                &large_content,
            );
        });
    });

    group.finish();
}

fn bench_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("tree");

    // Test with different tree depths/sizes
    for depth in [1, 3, 5] {
        let (_temp_dir, vault_path) = create_bench_vault();

        // Create nested directory structure
        fn create_nested(vault_path: &PathBuf, prefix: &str, depth: usize) {
            if depth == 0 {
                return;
            }
            for i in 0..3 {
                let dir_path = if prefix.is_empty() {
                    format!("/dir{i}")
                } else {
                    format!("{prefix}/dir{i}")
                };
                run_oxcrypt(vault_path, &["mkdir", &dir_path]);
                // Write file inside the directory we just created
                run_oxcrypt_with_stdin(vault_path, &["write", &format!("{dir_path}/file.txt")], b"x");
                create_nested(vault_path, &dir_path, depth - 1);
            }
        }

        create_nested(&vault_path, "", depth);

        group.bench_with_input(BenchmarkId::from_parameter(format!("depth_{depth}")), &vault_path, |b, path| {
            b.iter(|| {
                let success = run_oxcrypt(path, &["tree"]);
                black_box(success);
            });
        });
    }

    group.finish();
}

fn bench_mkdir(c: &mut Criterion) {
    let (_temp_dir, vault_path) = create_bench_vault();
    let mut counter = 0u64;

    c.bench_function("mkdir", |b| {
        b.iter(|| {
            counter += 1;
            let success = run_oxcrypt(&vault_path, &["mkdir", &format!("/dir{counter}")]);
            black_box(success);
        });
    });
}

fn bench_mkdir_parents(c: &mut Criterion) {
    let (_temp_dir, vault_path) = create_bench_vault();
    let mut counter = 0u64;

    c.bench_function("mkdir_with_parents", |b| {
        b.iter(|| {
            counter += 1;
            let success = run_oxcrypt(
                &vault_path,
                &["mkdir", "-p", &format!("/a{counter}/b{counter}/c{counter}")],
            );
            black_box(success);
        });
    });
}

fn bench_cp(c: &mut Criterion) {
    let (_temp_dir, vault_path) = create_bench_vault();

    // Create a source file
    let content = vec![b'x'; 100 * 1024]; // 100KB
    run_oxcrypt_with_stdin(&vault_path, &["write", "/source.txt"], &content);

    let mut counter = 0u64;

    c.bench_function("cp_100KB", |b| {
        b.iter(|| {
            counter += 1;
            let success = run_oxcrypt(&vault_path, &["cp", "/source.txt", &format!("/copy{counter}.txt")]);
            black_box(success);
        });
    });
}

fn bench_mv(c: &mut Criterion) {
    let (_temp_dir, vault_path) = create_bench_vault();
    let mut counter = 0u64;

    c.bench_function("mv", |b| {
        b.iter_with_setup(
            || {
                counter += 1;
                // Create a file to move
                run_oxcrypt_with_stdin(&vault_path, &["write", &format!("/tomove{counter}.txt")], b"content");
                counter
            },
            |i| {
                let success = run_oxcrypt(&vault_path, &["mv", &format!("/tomove{i}.txt"), &format!("/moved{i}.txt")]);
                black_box(success);
            },
        );
    });
}

fn bench_rm(c: &mut Criterion) {
    let (_temp_dir, vault_path) = create_bench_vault();
    let mut counter = 0u64;

    c.bench_function("rm", |b| {
        b.iter_with_setup(
            || {
                counter += 1;
                // Create a file to remove
                run_oxcrypt_with_stdin(&vault_path, &["write", &format!("/todelete{counter}.txt")], b"content");
                counter
            },
            |i| {
                let success = run_oxcrypt(&vault_path, &["rm", &format!("/todelete{i}.txt")]);
                black_box(success);
            },
        );
    });
}

criterion_group!(
    benches,
    bench_init,
    bench_ls,
    bench_cat,
    bench_write,
    bench_tree,
    bench_mkdir,
    bench_mkdir_parents,
    bench_cp,
    bench_mv,
    bench_rm,
);
criterion_main!(benches);
