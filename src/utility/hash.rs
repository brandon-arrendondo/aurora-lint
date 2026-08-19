use anyhow::Result;
use sha2::{Digest, Sha256};
use std::fs;

/// First 8 hex characters of `file_path`'s SHA-256 content hash.
pub fn calculate_file_hash(file_path: &str) -> Result<String> {
    let content = fs::read(file_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let result = hasher.finalize();
    Ok(format!("{:x}", result)[..8].to_string()) // First 8 chars of hash
}
