




/// Generate various test patterns (minimal set)
pub mod patterns {
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
#[allow(dead_code)] // Used in vault_integration_tests
pub mod sizes {
    pub const CHUNK_SIZE: usize = 32768; // 32 KB (one chunk)
    pub const LARGE: usize = 1024 * 1024; // 1 MB
    
    /// Sizes around chunk boundaries
    pub const CHUNK_MINUS_ONE: usize = CHUNK_SIZE - 1;
    pub const CHUNK_PLUS_ONE: usize = CHUNK_SIZE + 1;
    pub const TWO_CHUNKS: usize = CHUNK_SIZE * 2;
    pub const TWO_CHUNKS_PLUS_ONE: usize = TWO_CHUNKS + 1;
}