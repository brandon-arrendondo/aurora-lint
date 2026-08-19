//! Library interface for `sqc`, a static analysis tool checking C code
//! against the SEI CERT C Coding Standard (285 rules across 17 categories).
//! Exists to let `cargo test` exercise the analysis engine directly; the
//! `sqc` binary (`main.rs`) is a thin CLI wrapper around
//! [`analyze::analyze_project`]. See this crate's README for the full
//! feature set (export formats, diff-only mode, the optional TUI).
#![warn(missing_docs)]
#![allow(clippy::only_used_in_recursion)] // recursive &self on tree-sitter methods
#![allow(clippy::needless_borrow)] // &str refs in tree-sitter helper calls
#![allow(clippy::too_many_arguments)] // rule checker APIs naturally have many params
#![allow(clippy::collapsible_if)] // nested ifs are clearer in rule checker logic
#![allow(clippy::struct_field_names)] // File-prefixed fields in FileError enum

/// The analysis engine: [`analyze::analyze_project`] and every dataflow
/// pass (CFG, value-range, init-state, null-state) it composes.
pub mod analyze;
/// Writing violations out as CSV, XLSX, JSON, or SARIF 2.1.0.
pub mod export;
/// Project file discovery: which C files to analyze, and git-aware
/// diff-only scoping.
pub mod files;
/// The rule manifest schema ([`manifest::RuleManifest`]) and its TOML loading.
pub mod manifest;
/// Tree-sitter C parser setup ([`parser::CParser`]).
pub mod parser;
/// Progress reporting during a project scan (CLI and GUI implementations).
pub mod progress;
pub mod rules;
pub mod toolchain;
/// The optional interactive terminal UI (`--features tui`) for browsing and
/// managing violations.
#[cfg(feature = "tui")]
pub mod ui;
/// Shared helpers used across rule implementations (CERT C AST utilities,
/// path helpers, file hashing).
pub mod utility;

/// Common types and functions re-exported for a typical consumer, so most
/// uses need only `use sqc::prelude::*;`.
pub mod prelude {
    pub use crate::files::ProjectSource;
    pub use crate::manifest::{RuleManifest, Severity};
    pub use crate::rules::{CertRule, RuleRegistry, RuleViolation};
    pub use crate::utility::files::get_relative_path;
    pub use crate::utility::hash::calculate_file_hash;
    pub use anyhow::{Context, Result};
}
