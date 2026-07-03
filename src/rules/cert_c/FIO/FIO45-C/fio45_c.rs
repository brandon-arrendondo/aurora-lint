//! FIO45-C: Avoid TOCTOU race conditions while accessing files
//!
//! A TOCTOU (time-of-check, time-of-use) race condition is possible when two or more
//! concurrent processes are operating on a shared file system. Typically, the first
//! access is a check to verify some attribute of the file, followed by a call to use
//! the file. An attacker can alter the file between the two accesses, or replace the
//! file with a symbolic or hard link to a different file.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! void open_some_file(const char *file) {
//!   FILE *f = fopen(file, "r");  // Check if exists
//!   if (NULL != f) {
//!     /* File exists, handle error */
//!   } else {
//!     f = fopen(file, "w");  // Race window here
//!     if (NULL == f) {
//!       /* Handle error */
//!     }
//!     /* Write to file */
//!     fclose(f);
//!   }
//! }
//! ```
//!
//! **Compliant (C11):**
//! ```c
//! void open_some_file(const char *file) {
//!   FILE *f = fopen(file, "wx");  // Atomic: exclusive create and write
//!   if (NULL == f) {
//!     /* Handle error */
//!   }
//!   /* Write to file */
//!   fclose(f);
//! }
//! ```
//!
//! **Compliant (POSIX):**
//! ```c
//! void open_some_file(const char *file) {
//!   int fd = open(file, O_CREAT | O_EXCL | O_WRONLY);  // Atomic
//!   if (-1 != fd) {
//!     FILE *f = fdopen(fd, "w");
//!     if (NULL != f) {
//!       /* Write to file */
//!       fclose(f);
//!     }
//!   }
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Fio45C;

impl CertRule for Fio45C {
    fn rule_id(&self) -> &'static str {
        "FIO45-C"
    }

    fn description(&self) -> &'static str {
        "Avoid TOCTOU race conditions while accessing files"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "FIO45-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Track TOCTOU violations across the AST
        let mut tracker = ToctouTracker::new();
        tracker.analyze_node(node, source, &mut violations);

        violations
    }
}

struct ToctouTracker {
    // Track fopen() calls with their filename arguments within each scope
    // Key: scope identifier, Value: map of filename -> (fopen calls with that filename)
    fopen_calls: HashMap<usize, Vec<FopenCall>>,
}

#[derive(Clone)]
struct FopenCall {
    filename: String,
    mode: String,
    line: usize,
    column: usize,
}

impl ToctouTracker {
    fn new() -> Self {
        Self {
            fopen_calls: HashMap::new(),
        }
    }

    fn analyze_node(&mut self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Find function definitions to analyze
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            self.analyze_function(&func, source, violations);
        }
    }

    fn analyze_function(
        &mut self,
        func_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get a unique scope identifier for this function
        let scope_id = func_node.id();

        // Clear tracking for this scope
        self.fopen_calls.insert(scope_id, Vec::new());

        // Get function body
        if let Some(body) = func_node.child_by_field_name("body") {
            // Collect all fopen calls in this function
            self.collect_fopen_calls(&body, source, scope_id);

            // Check for TOCTOU patterns
            self.check_toctou_violations(scope_id, violations);
        }
    }

    fn collect_fopen_calls(&mut self, node: &Node, source: &str, scope_id: usize) {
        // Look for call expressions
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if func_name == "fopen" {
                    if let Some(args) = call.child_by_field_name("arguments") {
                        // Extract filename and mode arguments
                        if let Some((filename, mode)) = self.extract_fopen_args(&args, source) {
                            let calls = self.fopen_calls.entry(scope_id).or_default();
                            calls.push(FopenCall {
                                filename,
                                mode,
                                line: call.start_position().row + 1,
                                column: call.start_position().column + 1,
                            });
                        }
                    }
                }
            }
        }
    }

    fn extract_fopen_args(&self, args_node: &Node, source: &str) -> Option<(String, String)> {
        let args_text = get_node_text(args_node, source);

        // Parse arguments list (filename, mode)
        // This is a simplified parser that handles common patterns
        let args_str = args_text.trim_matches(|c| c == '(' || c == ')');
        let parts: Vec<&str> = args_str.split(',').collect();

        if parts.len() >= 2 {
            let filename = parts[0].trim().to_string();
            let mode = parts[1].trim().trim_matches('"').to_string();
            return Some((filename, mode));
        }

        None
    }

    fn check_toctou_violations(&self, scope_id: usize, violations: &mut Vec<RuleViolation>) {
        if let Some(calls) = self.fopen_calls.get(&scope_id) {
            // Group calls by filename
            let mut filename_groups: HashMap<String, Vec<&FopenCall>> = HashMap::new();

            for call in calls {
                filename_groups
                    .entry(call.filename.clone())
                    .or_default()
                    .push(call);
            }

            // Check each filename group for TOCTOU patterns
            for (filename, file_calls) in filename_groups.iter() {
                if file_calls.len() >= 2 {
                    // Multiple fopen calls on the same file - potential TOCTOU
                    // Check for the classic pattern: first open for read, then open for write
                    for i in 0..file_calls.len() - 1 {
                        let first_call = file_calls[i];

                        // Check if first call is a read check (mode "r")
                        if first_call.mode == "r" {
                            // Look for subsequent write calls
                            for second_call in file_calls.iter().skip(i + 1) {
                                // Check if second call is a write (mode "w", "a", etc.)
                                if second_call.mode.starts_with('w')
                                    || second_call.mode.starts_with('a')
                                {
                                    violations.push(RuleViolation {
                                        rule_id: "FIO45-C".to_string(),
                                        message: format!(
                                            "TOCTOU race condition: file '{}' opened multiple times (first for read at line {}, then for write at line {}). Use fopen() with \"wx\" mode or open() with O_CREAT | O_EXCL for atomic operation",
                                            filename,
                                            first_call.line,
                                            second_call.line
                                        ),
                                        severity: Severity::High,
                                        line: second_call.line,
                                        column: second_call.column,
                                        file_path: String::new(),
                                        suggestion: Some(format!(
                                            "Replace the check-then-open pattern with a single atomic fopen({}, \"wx\") call, or use POSIX open() with O_CREAT | O_EXCL | O_WRONLY flags",
                                            filename
                                        )),
                                        requires_manual_review: None,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
