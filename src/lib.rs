// Library interface for tools_scq
// This allows running tests via `cargo test`
#![allow(clippy::only_used_in_recursion)] // recursive &self on tree-sitter methods
#![allow(clippy::needless_borrow)] // &str refs in tree-sitter helper calls
#![allow(clippy::too_many_arguments)] // rule checker APIs naturally have many params
#![allow(clippy::collapsible_if)] // nested ifs are clearer in rule checker logic
#![allow(clippy::struct_field_names)] // File-prefixed fields in FileError enum

pub mod analyze;
pub mod export;
pub mod files;
pub mod manifest;
pub mod parser;
pub mod progress;
pub mod rules;
pub mod toolchain;
#[cfg(feature = "tui")]
pub mod ui;
pub mod utility;

// Prelude for common types and functions
pub mod prelude {
    pub use crate::files::ProjectSource;
    pub use crate::manifest::{RuleManifest, Severity};
    pub use crate::rules::{CertRule, RuleRegistry, RuleViolation};
    pub use crate::utility::files::get_relative_path;
    pub use crate::utility::hash::calculate_file_hash;
    pub use anyhow::{Context, Result};
}
