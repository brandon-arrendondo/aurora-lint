//! Common imports used throughout the aurora-lint project

// Re-export commonly used types and traits
pub use crate::manifest::RuleManifest;
pub use crate::rules::{RuleRegistry, RuleViolation};
pub use crate::utility::files::get_relative_path;
pub use crate::utility::hash::calculate_file_hash;

// Re-export common error handling
pub use anyhow::{Error, Result};

// Re-export common standard library items
pub use std::collections::HashMap;
pub use std::fs;
pub use std::path::{Path, PathBuf};

// Re-export commonly used external crates
pub use serde::{Deserialize, Serialize};
