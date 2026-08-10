//! FIO05-C: Identify files using multiple file attributes
//!
//! Files can often be identified by attributes other than the file name, such as by
//! comparing file ownership or creation time. Information about a file that has been
//! created and closed can be stored and then used to validate the identity of the
//! file when it is reopened.
//!
//! Comparing multiple attributes of the file increases the likelihood that the
//! reopened file is the same file that had been previously operated on.
//!
//! ## Violations:
//!
//! **Noncompliant Code Example (Reopen):**
//! ```c
//! char *file_name;
//! FILE *fd = fopen(file_name, "w");
//! if (fd == NULL) { /* Handle error */ }
//! /* Write to file */
//! fclose(fd);
//! fd = NULL;
//! /* Race condition window - attacker can switch file */
//! fd = fopen(file_name, "r");  // VIOLATION: Reopening by name only
//! if (fd == NULL) { /* Handle error */ }
//! /* Read from file */
//! fclose(fd);
//! ```
//!
//! ## Compliant Solutions:
//!
//! **Compliant Solution (POSIX Device/I-node):**
//! ```c
//! struct stat orig_st;
//! struct stat new_st;
//! char *file_name;
//!
//! int fd = open(file_name, O_WRONLY);
//! if (fd == -1) { /* Handle error */ }
//! /* Write to file */
//! if (fstat(fd, &orig_st) == -1) { /* Handle error */ }
//! close(fd);
//!
//! fd = open(file_name, O_RDONLY);
//! if (fd == -1) { /* Handle error */ }
//! if (fstat(fd, &new_st) == -1) { /* Handle error */ }
//!
//! if ((orig_st.st_dev != new_st.st_dev) ||
//!     (orig_st.st_ino != new_st.st_ino)) {
//!   /* File was tampered with! */
//! }
//! ```
//!
//! **Compliant Solution (Open Only Once):**
//! ```c
//! int fd = open(file_name, O_RDWR);
//! if (fd == -1) { /* Handle error */ }
//! /* Write to file */
//! /* Read from file (no close/reopen needed) */
//! close(fd);
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Fio05C;

impl CertRule for Fio05C {
    fn rule_id(&self) -> &'static str {
        "FIO05-C"
    }

    fn description(&self) -> &'static str {
        "Identify files using multiple file attributes"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "FIO05-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // The analysis harness always calls check() with the translation_unit
        // root, so scope each function_definition individually with a FRESH
        // FileReopenAnalyzer (fresh file_operations map) per function. This
        // keeps reopen-pattern/fstat sequencing checks from merging unrelated
        // functions' same-named FILE*/fd variables into one file-wide timeline.
        if node.kind() == "translation_unit" {
            for func in query::find_descendants_of_kind(*node, "function_definition") {
                let mut analyzer = FileReopenAnalyzer::new();
                analyzer.analyze_scope(&func, source, &mut violations);
            }
            return violations;
        }

        // Analyze each function for file reopen violations (this node itself, if it is
        // a function_definition, plus any nested function definitions within it)
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            let mut analyzer = FileReopenAnalyzer::new();
            analyzer.analyze_scope(&func, source, &mut violations);
        }

        violations
    }
}

/// Tracks file operations to detect unsafe reopen patterns
struct FileReopenAnalyzer {
    /// Track file operations: filename -> list of operations
    file_operations: HashMap<String, Vec<FileOperation>>,
    /// Track fstat() calls and their associated file descriptors
    fstat_calls: HashSet<String>,
    /// Track file attribute comparisons (st_dev, st_ino, etc.)
    has_attribute_comparison: bool,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct FileOperation {
    op_type: OpType,
    filename: String,
    fd_var: Option<String>, // File descriptor or FILE* variable
    line: usize,
    column: usize,
    node_id: usize,
    is_read_mode: bool, // True if opening in read mode (needs ownership check)
}

#[derive(Clone, Debug, PartialEq)]
enum OpType {
    Open,
    Close,
    Fstat,
}

impl FileReopenAnalyzer {
    fn new() -> Self {
        Self {
            file_operations: HashMap::new(),
            fstat_calls: HashSet::new(),
            has_attribute_comparison: false,
        }
    }

    fn analyze_scope(
        &mut self,
        scope_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // First pass: collect all file operations
        // For functions, look in body; for translation_unit, analyze the whole node
        if scope_node.kind() == "function_definition" {
            if let Some(body) = scope_node.child_by_field_name("body") {
                self.collect_operations(&body, source);
            }
        } else {
            // Global scope (translation_unit) - analyze entire scope
            self.collect_operations(scope_node, source);
        }

        // Second pass: detect violations
        self.detect_reopen_violations(violations);
    }

    fn collect_operations(&mut self, node: &Node, source: &str) {
        for n in query::find_descendants(*node, |n| {
            matches!(
                n.kind(),
                "call_expression" | "assignment_expression" | "declaration" | "binary_expression"
            )
        }) {
            match n.kind() {
                "call_expression" => {
                    self.process_call(&n, source);
                }
                "assignment_expression" => {
                    // Check for fopen() assigned to a variable
                    self.process_assignment(&n, source);
                }
                "declaration" => {
                    // Check for declarations with fopen() initializers
                    self.process_declaration(&n, source);
                }
                "binary_expression" => {
                    // Check for file attribute comparisons (st_dev, st_ino)
                    self.check_attribute_comparison(&n, source);
                }
                _ => {}
            }
        }
    }

    fn process_call(&mut self, node: &Node, source: &str) {
        if let Some(function) = node.child_by_field_name("function") {
            let func_name = ast_utils::get_node_text_owned(&function, source);

            match func_name.as_str() {
                "fopen" | "open" => {
                    self.process_open_call(node, source, &func_name);
                }
                "fclose" | "close" => {
                    self.process_close_call(node, source, &func_name);
                }
                "fstat" | "stat" | "lstat" => {
                    self.process_fstat_call(node, source, &func_name);
                }
                _ => {}
            }
        }
    }

    fn process_assignment(&mut self, node: &Node, source: &str) {
        if let Some(right) = node.child_by_field_name("right") {
            if right.kind() == "call_expression" {
                if let Some(function) = right.child_by_field_name("function") {
                    let func_name = ast_utils::get_node_text_owned(&function, source);
                    if func_name == "fopen" || func_name == "open" {
                        // Get the variable being assigned
                        if let Some(left) = node.child_by_field_name("left") {
                            let var_name = ast_utils::get_node_text_owned(&left, source);
                            self.process_open_call_with_var(
                                &right,
                                source,
                                &func_name,
                                Some(var_name),
                            );
                        }
                    }
                }
            }
        }
    }

    fn process_declaration(&mut self, node: &Node, source: &str) {
        // Handle declarations like: FILE *fd = fopen(...)
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "init_declarator" {
                    // Get the declarator (variable name)
                    if let Some(declarator) = child.child_by_field_name("declarator") {
                        let var_name = self.extract_identifier_name(&declarator, source);

                        // Get the value (initializer)
                        if let Some(value) = child.child_by_field_name("value") {
                            if value.kind() == "call_expression" {
                                if let Some(function) = value.child_by_field_name("function") {
                                    let func_name =
                                        ast_utils::get_node_text_owned(&function, source);
                                    if func_name == "fopen" || func_name == "open" {
                                        self.process_open_call_with_var(
                                            &value,
                                            source,
                                            &func_name,
                                            Some(var_name),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn extract_identifier_name(&self, declarator: &Node, source: &str) -> String {
        // Handle different declarator types (pointer_declarator, identifier, etc.)
        match declarator.kind() {
            "identifier" => ast_utils::get_node_text_owned(declarator, source),
            "pointer_declarator" | "array_declarator" | "function_declarator" => {
                // Recursively find the identifier
                for i in 0..declarator.child_count() {
                    if let Some(child) = declarator.child(i) {
                        if child.kind() == "identifier" {
                            return ast_utils::get_node_text_owned(&child, source);
                        }
                        let name = self.extract_identifier_name(&child, source);
                        if !name.is_empty() {
                            return name;
                        }
                    }
                }
                String::new()
            }
            _ => String::new(),
        }
    }

    fn process_open_call(&mut self, node: &Node, source: &str, func_name: &str) {
        self.process_open_call_with_var(node, source, func_name, None);
    }

    fn process_open_call_with_var(
        &mut self,
        node: &Node,
        source: &str,
        func_name: &str,
        fd_var: Option<String>,
    ) {
        if let Some(arguments) = node.child_by_field_name("arguments") {
            // Extract filename argument (first argument for both fopen and open)
            if let Some(filename_node) = self.get_first_argument(&arguments) {
                let filename = ast_utils::get_node_text_owned(&filename_node, source);

                // Check if open mode suggests reading existing file (needs ownership check)
                let is_read_mode = self.is_read_mode(&arguments, source, func_name);

                let op = FileOperation {
                    op_type: OpType::Open,
                    filename: filename.clone(),
                    fd_var,
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    node_id: node.id(),
                    is_read_mode,
                };

                self.file_operations.entry(filename).or_default().push(op);
            }
        }
    }

    /// Check if open mode suggests reading existing file content
    fn is_read_mode(&self, arguments: &Node, source: &str, func_name: &str) -> bool {
        // Get the mode argument (2nd for fopen, varies for open)
        let args: Vec<_> = (0..arguments.child_count())
            .filter_map(|i| arguments.child(i))
            .filter(|n| !matches!(n.kind(), "," | "(" | ")"))
            .collect();

        if func_name == "fopen" && args.len() >= 2 {
            let mode = ast_utils::get_node_text_owned(&args[1], source);
            // "r" and "r+" read existing file; "w", "w+", "a", "a+" create/truncate
            return mode.contains("\"r") || mode.contains("'r");
        }

        if func_name == "open" && args.len() >= 2 {
            let flags = ast_utils::get_node_text_owned(&args[1], source);
            // O_RDONLY or O_RDWR without O_CREAT suggests reading existing
            let has_rdonly = flags.contains("O_RDONLY");
            let has_rdwr = flags.contains("O_RDWR");
            let has_creat = flags.contains("O_CREAT");
            return (has_rdonly || has_rdwr) && !has_creat;
        }

        false
    }

    fn process_close_call(&mut self, node: &Node, source: &str, _func_name: &str) {
        if let Some(arguments) = node.child_by_field_name("arguments") {
            // Get the file descriptor/FILE* being closed
            if let Some(fd_node) = self.get_first_argument(&arguments) {
                let fd_var = ast_utils::get_node_text_owned(&fd_node, source);

                // Try to match this close with a previous open by fd_var
                // We'll mark this as a close operation for the associated filename
                for (filename, ops) in &mut self.file_operations {
                    // Find the most recent open with matching fd_var
                    if let Some(_last_open) = ops.iter().rev().find(|op| {
                        op.op_type == OpType::Open
                            && op.fd_var.as_ref().map(|v| v == &fd_var).unwrap_or(false)
                    }) {
                        let close_op = FileOperation {
                            op_type: OpType::Close,
                            filename: filename.clone(),
                            fd_var: Some(fd_var.clone()),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            node_id: node.id(),
                            is_read_mode: false,
                        };
                        ops.push(close_op);
                        break;
                    }
                }
            }
        }
    }

    fn process_fstat_call(&mut self, node: &Node, source: &str, _func_name: &str) {
        if let Some(arguments) = node.child_by_field_name("arguments") {
            // fstat(fd, &buf) - first argument is file descriptor
            if let Some(fd_node) = self.get_first_argument(&arguments) {
                let fd_var = ast_utils::get_node_text_owned(&fd_node, source);
                self.fstat_calls.insert(fd_var.clone());

                // Also track as an fstat operation for analysis
                for (filename, ops) in &mut self.file_operations {
                    if let Some(_last_open) = ops.iter().rev().find(|op| {
                        op.op_type == OpType::Open
                            && op.fd_var.as_ref().map(|v| v == &fd_var).unwrap_or(false)
                    }) {
                        let fstat_op = FileOperation {
                            op_type: OpType::Fstat,
                            filename: filename.clone(),
                            fd_var: Some(fd_var),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            node_id: node.id(),
                            is_read_mode: false,
                        };
                        ops.push(fstat_op);
                        break;
                    }
                }
            }
        }
    }

    fn check_attribute_comparison(&mut self, node: &Node, source: &str) {
        // Look for comparisons involving st_dev, st_ino, st_mode, etc.
        let text = ast_utils::get_node_text_owned(node, source);

        if text.contains("st_dev")
            || text.contains("st_ino")
            || text.contains("st_mode")
            || text.contains("st_uid")
            || text.contains("st_gid")
        {
            self.has_attribute_comparison = true;
        }
    }

    fn get_first_argument<'a>(&self, arguments: &'a Node) -> Option<Node<'a>> {
        for i in 0..arguments.child_count() {
            if let Some(arg) = arguments.child(i) {
                if !matches!(arg.kind(), "," | "(" | ")") {
                    return Some(arg);
                }
            }
        }
        None
    }

    fn detect_reopen_violations(&self, violations: &mut Vec<RuleViolation>) {
        // Check each filename for reopen patterns
        for (filename, ops) in &self.file_operations {
            // Check 1: Open -> Close -> Open (without proper fstat checks)
            self.check_reopen_pattern(filename, ops, violations);

            // Check 2: Open with variable filename (not string literal) without fstat validation
            self.check_unvalidated_open(filename, ops, violations);
        }
    }

    fn check_unvalidated_open(
        &self,
        filename: &str,
        ops: &[FileOperation],
        violations: &mut Vec<RuleViolation>,
    ) {
        // Skip if filename is a string literal (starts with " or ')
        let trimmed = filename.trim();
        if trimmed.starts_with('"') || trimmed.starts_with('\'') {
            return;
        }

        // Look for open operations in READ MODE without subsequent fstat + attribute comparison
        for op in ops {
            if op.op_type == OpType::Open && op.is_read_mode {
                // Check if there's an fstat for this file descriptor
                let has_fstat = ops.iter().any(|o| {
                    o.op_type == OpType::Fstat
                        && o.fd_var.is_some()
                        && op.fd_var.is_some()
                        && o.fd_var == op.fd_var
                });

                // If no fstat AND no attribute comparison, it's a violation
                if !has_fstat && !self.has_attribute_comparison {
                    violations.push(RuleViolation {
                        rule_id: "FIO05-C".to_string(),
                        severity: Severity::Medium,
                        message: format!(
                            "File opened for reading using variable filename '{}' without verifying file attributes (fstat + st_uid/st_gid check)",
                            filename
                        ),
                        file_path: String::new(),
                        line: op.line,
                        column: op.column,
                        suggestion: Some(
                            "Use fstat() to check file ownership (st_uid, st_gid) before reading untrusted files"
                                .to_string(),
                        ),
                        ..Default::default()
                    });
                    return; // Only report once per filename
                }
            }
        }
    }

    fn check_reopen_pattern(
        &self,
        filename: &str,
        ops: &[FileOperation],
        violations: &mut Vec<RuleViolation>,
    ) {
        // Track state: looking for Open -> Close -> Open sequences
        let mut i = 0;
        while i < ops.len() {
            if ops[i].op_type == OpType::Open {
                let first_open = &ops[i];

                // Look for a subsequent close
                let mut j = i + 1;
                while j < ops.len() {
                    if ops[j].op_type == OpType::Close {
                        let close_op = &ops[j];

                        // Check if this close matches the open (same fd_var)
                        let is_matching_close = first_open.fd_var.is_some()
                            && close_op.fd_var.is_some()
                            && first_open.fd_var == close_op.fd_var;

                        if is_matching_close {
                            // Look for a subsequent reopen of the same file
                            let mut k = j + 1;
                            while k < ops.len() {
                                if ops[k].op_type == OpType::Open && ops[k].filename == *filename {
                                    // Found a reopen! Check if there's proper validation
                                    let has_fstat_between = self.has_fstat_between(i, k, ops);

                                    if !has_fstat_between && !self.has_attribute_comparison {
                                        // VIOLATION: Reopening file without proper validation
                                        violations.push(RuleViolation {
                                            rule_id: "FIO05-C".to_string(),
                                            severity: Severity::Medium,
                                            message: format!(
                                                "File reopened using filename '{}' without verifying file attributes (st_dev, st_ino)",
                                                filename
                                            ),
                                            file_path: String::new(),
                                            line: ops[k].line,
                                            column: ops[k].column,
                                            suggestion: Some(
                                                "Use fstat() to check st_dev and st_ino before and after reopening, or avoid closing and reopening the file".to_string()
                                            ),
                                            ..Default::default()
                                        });
                                    }

                                    // Move to next potential violation
                                    i = k;
                                    break;
                                }
                                k += 1;
                            }
                            break;
                        }
                    }
                    j += 1;
                }
            }
            i += 1;
        }
    }

    fn has_fstat_between(&self, start_idx: usize, end_idx: usize, ops: &[FileOperation]) -> bool {
        // Check if there's an fstat operation between start and end indices
        for op in ops
            .iter()
            .take(end_idx.min(ops.len() - 1) + 1)
            .skip(start_idx)
        {
            if op.op_type == OpType::Fstat {
                return true;
            }
        }
        false
    }
}
