use anyhow::Result;
use sha2::{Digest, Sha256};
use std::fs;

/// Lowercase hex SHA-256 of `content`.
pub fn sha256_hex(content: &[u8]) -> String {
    format!("{:x}", Sha256::digest(content))
}

/// First 8 hex characters of `file_path`'s SHA-256 content hash.
pub fn calculate_file_hash(file_path: &str) -> Result<String> {
    Ok(sha256_hex(&fs::read(file_path)?)[..8].to_string())
}
