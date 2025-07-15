use oxidized_cryptolib::crypto::keys::MasterKey;
use secrecy::Secret;

/// Collection of test vectors and known good values for regression testing
pub mod test_vectors {
    use super::*;
    
    /// Known master key for test vector validation
    pub fn known_master_key() -> MasterKey {
        MasterKey {
            aes_master_key: Secret::new([
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            ]),
            mac_master_key: Secret::new([
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
            ]),
        }
    }
}

/// Generate various test patterns
pub mod patterns {
    /// Generate a repeating pattern of specified size
    pub fn repeating_pattern(pattern: &[u8], size: usize) -> Vec<u8> {
        pattern.iter()
            .cycle()
            .take(size)
            .cloned()
            .collect()
    }
    
    /// Generate binary data with all byte values
    pub fn all_bytes_pattern() -> Vec<u8> {
        (0u8..=255).collect()
    }
    
    /// Generate random-looking but deterministic data
    pub fn pseudo_random_data(size: usize, seed: u8) -> Vec<u8> {
        let mut data = Vec::with_capacity(size);
        let mut value = seed;
        
        for _ in 0..size {
            data.push(value);
            value = value.wrapping_mul(31).wrapping_add(17);
        }
        
        data
    }
    
    /// Generate compressible data (for testing compression scenarios)
    pub fn compressible_data(size: usize) -> Vec<u8> {
        let pattern = b"AAAAAAAAAA";
        repeating_pattern(pattern, size)
    }
    
    /// Generate incompressible data
    pub fn incompressible_data(size: usize) -> Vec<u8> {
        pseudo_random_data(size, 42)
    }
}

/// File size constants for testing
pub mod sizes {
    pub const CHUNK_SIZE: usize = 32768;           // 32 KB (one chunk)
    pub const LARGE: usize = 1024 * 1024;          // 1 MB
    
    /// Sizes around chunk boundaries
    pub const CHUNK_MINUS_ONE: usize = CHUNK_SIZE - 1;
    pub const CHUNK_PLUS_ONE: usize = CHUNK_SIZE + 1;
    pub const TWO_CHUNKS: usize = CHUNK_SIZE * 2;
    pub const TWO_CHUNKS_PLUS_ONE: usize = TWO_CHUNKS + 1;
}

/// Directory structure patterns
pub mod structures {
    use crate::common::test_structures::FileEntry;
    
    /// Create a deeply nested directory structure
    pub fn deep_nesting(depth: usize) -> Vec<FileEntry> {
        let mut entries = Vec::new();
        let mut path = String::new();
        
        for i in 0..depth {
            if !path.is_empty() {
                path.push('/');
            }
            path.push_str(&format!("level{i}"));
            
            entries.push(FileEntry {
                path: Box::leak(format!("{path}/file{i}.txt").into_boxed_str()),
                content: format!("Content at level {i}").into_bytes(),
            });
        }
        
        entries
    }
    
    /// Create a wide directory structure (many files in one directory)
    pub fn wide_structure(width: usize) -> Vec<FileEntry> {
        (0..width)
            .map(|i| FileEntry {
                path: Box::leak(format!("file{i:04}.txt").into_boxed_str()),
                content: format!("File {i} content").into_bytes(),
            })
            .collect()
    }
    
    /// Create a balanced tree structure
    pub fn balanced_tree(depth: usize, branching_factor: usize) -> Vec<FileEntry> {
        let mut entries = Vec::new();
        
        fn add_level(
            entries: &mut Vec<FileEntry>,
            path: String,
            current_depth: usize,
            max_depth: usize,
            branching_factor: usize,
        ) {
            if current_depth >= max_depth {
                return;
            }
            
            for i in 0..branching_factor {
                let dir_name = format!("dir{i}");
                let dir_path = if path.is_empty() {
                    dir_name.clone()
                } else {
                    format!("{path}/{dir_name}")
                };
                
                // Add a file in this directory
                entries.push(FileEntry {
                    path: Box::leak(format!("{dir_path}/file.txt").into_boxed_str()),
                    content: format!("File in {dir_path}").into_bytes(),
                });
                
                // Recurse
                add_level(entries, dir_path, current_depth + 1, max_depth, branching_factor);
            }
        }
        
        add_level(&mut entries, String::new(), 0, depth, branching_factor);
        entries
    }
}

/// Performance testing utilities
pub mod performance {
    use std::time::{Duration, Instant};
    
    /// Measure the time taken by a closure
    pub fn measure_time<F, R>(f: F) -> (R, Duration)
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = f();
        let duration = start.elapsed();
        (result, duration)
    }
    
    /// Run a benchmark multiple times and return statistics
    pub struct BenchmarkResult {
        pub min: Duration,
        pub max: Duration,
        pub mean: Duration,
        pub iterations: usize,
    }
    
    pub fn benchmark<F>(iterations: usize, mut f: F) -> BenchmarkResult
    where
        F: FnMut(),
    {
        let mut durations = Vec::with_capacity(iterations);
        
        for _ in 0..iterations {
            let start = Instant::now();
            f();
            durations.push(start.elapsed());
        }
        
        let min = durations.iter().min().cloned().unwrap();
        let max = durations.iter().max().cloned().unwrap();
        let sum: Duration = durations.iter().sum();
        let mean = sum / iterations as u32;
        
        BenchmarkResult {
            min,
            max,
            mean,
            iterations,
        }
    }
}