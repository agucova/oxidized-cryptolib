use criterion::{black_box, criterion_group, criterion_main, Criterion};
use oxidized_cryptolib::vault::master_key::MasterKeyFile;

fn bench_vault_unlock(c: &mut Criterion) {
    let mut group = c.benchmark_group("vault_unlock");
    
    // Load the test vault configuration
    let masterkey_contents = include_str!("../test_vault/masterkey.cryptomator");
    
    group.bench_function("unlock_with_scrypt", |b| {
        b.iter(|| {
            // Parse and unlock master key file (includes scrypt key derivation)
            let master_key_file: MasterKeyFile = serde_json::from_str(masterkey_contents).unwrap();
            let master_key = master_key_file.unlock("123456789");
            
            black_box(master_key);
        });
    });
    
    group.finish();
}

fn bench_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_derivation");
    
    let masterkey_contents = include_str!("../test_vault/masterkey.cryptomator");
    let master_key_file: MasterKeyFile = serde_json::from_str(masterkey_contents).unwrap();
    
    // Test different password lengths (realistic scenarios)
    // Note: Only the correct password "123456789" will work with this test vault
    let passwords = [
        ("correct_password", b"123456789".as_slice()),
    ];
    
    for (name, password) in passwords {
        group.bench_function(name, |b| {
            b.iter(|| {
                let password_str = std::str::from_utf8(password).unwrap();
                let master_key = master_key_file.unlock(password_str);
                black_box(master_key);
            });
        });
    }
    
    group.finish();
}

fn bench_vault_initialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("vault_initialization");
    
    // Benchmark creating a new vault (useful for vault creation tools)
    group.bench_function("create_new_vault", |b| {
        b.iter(|| {
            // Generate new master keys
            let master_key = oxidized_cryptolib::crypto::keys::MasterKey::random();
            
            // Create vault configuration
            let vault_id = uuid::Uuid::new_v4().to_string();
            let format = 8;
            let cipher_combo = "SIV_GCM".to_string();
            
            // In reality, this would create the full JWT structure
            black_box((master_key, vault_id, format, cipher_combo));
        });
    });
    
    group.finish();
}

fn bench_complete_vault_unlock(c: &mut Criterion) {
    let mut group = c.benchmark_group("complete_vault_unlock");
    
    // Load both vault config and master key file
    let vault_config = include_str!("../test_vault/vault.cryptomator");
    let masterkey_contents = include_str!("../test_vault/masterkey.cryptomator");
    
    group.bench_function("parse_and_unlock", |b| {
        b.iter(|| {
            // Parse vault config (would validate JWT in real implementation)
            let _vault_config_parsed = vault_config;
            
            // Unlock master key
            let master_key_file: MasterKeyFile = serde_json::from_str(masterkey_contents).unwrap();
            let master_key = master_key_file.unlock("123456789");
            
            black_box(master_key);
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_vault_unlock,
    bench_key_derivation,
    bench_vault_initialization,
    bench_complete_vault_unlock
);
criterion_main!(benches);