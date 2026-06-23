//! FIO42-C: Close files when they are no longer needed
//!
//! A call to fopen() or freopen() must be matched with a call to fclose()
//! before the lifetime of the last pointer that stores the return value ends
//! or before normal program termination.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! void process_file(const char *filename) {
//!     FILE *fp = fopen(filename, "r");
//!     if (fp == NULL) {
//!         return;
//!     }
//!     // ... process file ...
//!     return; // FILE* leak - fclose() never called
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! void process_file(const char *filename) {
//!     FILE *fp = fopen(filename, "r");
//!     if (fp == NULL) {
//!         return;
//!     }
//!     // ... process file ...
//!     if (fclose(fp) != 0) {
//!         // Handle error
//!     }
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Fio42C;

impl CertRule for Fio42C {
    fn rule_id(&self) -> &'static str {
        "FIO42-C"
    }

    fn description(&self) -> &'static str {
        "Close files when they are no longer needed"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "FIO42-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Track file resources across the AST
        let mut tracker = FileResourceTracker::new();
        tracker.analyze_node(node, source, &mut violations);

        violations
    }
}

struct FileResourceTracker {
    // Track FILE* variables from fopen/freopen
    file_pointers: HashMap<String, ResourceInfo>,
    // Track file descriptors from open()
    file_descriptors: HashMap<String, ResourceInfo>,
    // Track HANDLEs from CreateFile()
    file_handles: HashMap<String, ResourceInfo>,
    // Track which resources have been closed
    closed_resources: HashSet<String>,
}

#[derive(Clone)]
#[allow(dead_code)]
struct ResourceInfo {
    var_name: String,
    resource_type: ResourceType,
    line: usize,
    column: usize,
}

#[derive(Clone, PartialEq)]
#[allow(clippy::enum_variant_names)]
enum ResourceType {
    FilePointer,    // FILE* from fopen/freopen
    FileDescriptor, // int fd from open()
    FileHandle,     // HANDLE from CreateFile()
}

impl FileResourceTracker {
    fn new() -> Self {
        Self {
            file_pointers: HashMap::new(),
            file_descriptors: HashMap::new(),
            file_handles: HashMap::new(),
            closed_resources: HashSet::new(),
        }
    }

    fn analyze_node(&mut self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // First pass: find function definitions to analyze
        if node.kind() == "function_definition" {
            self.analyze_function(node, source, violations);
        }

        // Recurse to find all functions
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.analyze_node(&child, source, violations);
            }
        }
    }

    fn analyze_function(
        &mut self,
        func_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Reset tracking for this function scope
        self.file_pointers.clear();
        self.file_descriptors.clear();
        self.file_handles.clear();
        self.closed_resources.clear();

        // Get function body
        if let Some(body) = func_node.child_by_field_name("body") {
            // Collect all resource allocations
            self.collect_resources(&body, source);

            // Collect all resource deallocations
            self.collect_closes(&body, source);

            // Check for unclosed resources
            self.check_unclosed_resources(violations);

            // CWE-459: check for temp file creation without cleanup
            self.check_temp_file_cleanup(&body, source, violations);
        }
    }

    fn collect_resources(&mut self, node: &Node, source: &str) {
        match node.kind() {
            "declaration" => {
                self.check_file_pointer_declaration(node, source);
            }
            "assignment_expression" => {
                self.check_file_pointer_assignment(node, source);
            }
            _ => {}
        }

        // Recurse
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_resources(&child, source);
            }
        }
    }

    fn check_file_pointer_declaration(&mut self, node: &Node, source: &str) {
        // Classify each initialized declarator by the actual function it calls.
        // Substring matching is unsound here because `fopen(`/`freopen(` both
        // contain `open(`, which would otherwise track a FILE* as both a FILE
        // pointer and a POSIX file descriptor (task 223).
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        if let Some(rtype) = Self::callee_name(&value, source)
                            .as_deref()
                            .and_then(Self::classify_callee)
                        {
                            if let Some(var_name) = self.extract_declarator_name(&child, source) {
                                self.track_resource(var_name, rtype, node);
                            }
                        }
                    }
                }
            }
        }
    }

    fn check_file_pointer_assignment(&mut self, node: &Node, source: &str) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            // Classify by the called function, not by substring, so an `fopen`
            // RHS is tracked only as a FILE pointer and not also as a POSIX file
            // descriptor (`fopen(` contains `open(`) — see task 223.
            if let Some(rtype) = Self::callee_name(&right, source)
                .as_deref()
                .and_then(Self::classify_callee)
            {
                let var_name = get_node_text(&left, source).to_string();
                self.track_resource(var_name, rtype, node);
            }
        }
    }

    /// Record an opened resource of the given kind, keyed on the variable that
    /// holds it, positioned at `node`.
    fn track_resource(&mut self, var_name: String, rtype: ResourceType, node: &Node) {
        let info = ResourceInfo {
            var_name: var_name.clone(),
            resource_type: rtype.clone(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
        };
        match rtype {
            ResourceType::FilePointer => self.file_pointers.insert(var_name, info),
            ResourceType::FileDescriptor => self.file_descriptors.insert(var_name, info),
            ResourceType::FileHandle => self.file_handles.insert(var_name, info),
        };
    }

    /// Name of the first function called within an initializer / RHS expression
    /// (e.g. `fopen` from `fopen(...)` or `(FILE *)fopen(...)`).
    fn callee_name(node: &Node, source: &str) -> Option<String> {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                return Some(get_node_text(&function, source).trim().to_string());
            }
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(name) = Self::callee_name(&child, source) {
                    return Some(name);
                }
            }
        }
        None
    }

    /// Map an opener function name to the kind of resource it returns. Returns
    /// `None` for functions this rule does not track.
    fn classify_callee(name: &str) -> Option<ResourceType> {
        match name {
            "fopen" | "freopen" => Some(ResourceType::FilePointer),
            "open" => Some(ResourceType::FileDescriptor),
            "CreateFile" | "CreateFileA" | "CreateFileW" => Some(ResourceType::FileHandle),
            _ => None,
        }
    }

    fn collect_closes(&mut self, node: &Node, source: &str) {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                // Track fclose() calls
                if func_name == "fclose" {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        let args_text = get_node_text(&args, source);
                        let var_name = args_text.trim_matches(|c| c == '(' || c == ')').trim();
                        self.closed_resources.insert(var_name.to_string());
                    }
                }

                // Track POSIX close() calls
                if func_name == "close" {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        let args_text = get_node_text(&args, source);
                        let var_name = args_text.trim_matches(|c| c == '(' || c == ')').trim();
                        self.closed_resources.insert(var_name.to_string());
                    }
                }

                // Track Windows CloseHandle() calls
                if func_name == "CloseHandle" {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        let args_text = get_node_text(&args, source);
                        let var_name = args_text.trim_matches(|c| c == '(' || c == ')').trim();
                        self.closed_resources.insert(var_name.to_string());
                    }
                }
            }
        }

        // Recurse
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_closes(&child, source);
            }
        }
    }

    fn check_unclosed_resources(&self, violations: &mut Vec<RuleViolation>) {
        // Check FILE* pointers
        for (var_name, info) in &self.file_pointers {
            if !self.closed_resources.contains(var_name) {
                violations.push(RuleViolation {
                    rule_id: "FIO42-C".to_string(),
                    message: format!(
                        "FILE pointer '{}' opened with fopen/freopen but never closed with fclose()",
                        var_name
                    ),
                    severity: Severity::High,
                    line: info.line,
                    column: info.column,
                    file_path: String::new(),
                    suggestion: Some(format!(
                        "Add fclose({}) before function returns or program exits",
                        var_name
                    )),
                    requires_manual_review: None,
                });
            }
        }

        // Check file descriptors
        for (var_name, info) in &self.file_descriptors {
            if !self.closed_resources.contains(var_name) {
                violations.push(RuleViolation {
                    rule_id: "FIO42-C".to_string(),
                    message: format!(
                        "File descriptor '{}' opened with open() but never closed with close()",
                        var_name
                    ),
                    severity: Severity::High,
                    line: info.line,
                    column: info.column,
                    file_path: String::new(),
                    suggestion: Some(format!(
                        "Add close({}) before function returns or program exits",
                        var_name
                    )),
                    requires_manual_review: None,
                });
            }
        }

        // Check Windows HANDLEs
        for (var_name, info) in &self.file_handles {
            if !self.closed_resources.contains(var_name) {
                violations.push(RuleViolation {
                    rule_id: "FIO42-C".to_string(),
                    message: format!(
                        "File HANDLE '{}' opened with CreateFile() but never closed with CloseHandle()",
                        var_name
                    ),
                    severity: Severity::High,
                    line: info.line,
                    column: info.column,
                    file_path: String::new(),
                    suggestion: Some(format!(
                        "Add CloseHandle({}) before function returns or program exits",
                        var_name
                    )),
                    requires_manual_review: None,
                });
            }
        }
    }

    fn extract_declarator_name(&self, node: &Node, source: &str) -> Option<String> {
        if let Some(declarator) = node.child_by_field_name("declarator") {
            return self.find_identifier(&declarator, source);
        }
        None
    }

    fn find_identifier(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source).to_string());
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(name) = self.find_identifier(&child, source) {
                    return Some(name);
                }
            }
        }

        None
    }

    // ── CWE-459: Temp file creation without cleanup ─────────────────────────

    /// Check if a function creates temp files but never deletes them
    fn check_temp_file_cleanup(
        &self,
        body: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let mut temp_creations: Vec<(usize, usize)> = Vec::new();
        let mut has_cleanup = false;
        self.scan_temp_file_calls(body, source, &mut temp_creations, &mut has_cleanup);

        if !has_cleanup {
            for (line, col) in &temp_creations {
                violations.push(RuleViolation {
                    rule_id: "FIO42-C".to_string(),
                    message:
                        "Temporary file created but never deleted (missing unlink/remove call)"
                            .to_string(),
                    severity: Severity::Medium,
                    line: *line,
                    column: *col,
                    file_path: String::new(),
                    suggestion: Some(
                        "Call unlink() or remove() on the temporary file before function returns"
                            .to_string(),
                    ),
                    requires_manual_review: None,
                });
            }
        }
    }

    /// Recursively scan for temp file creation and cleanup calls
    fn scan_temp_file_calls(
        &self,
        node: &Node,
        source: &str,
        temp_creations: &mut Vec<(usize, usize)>,
        has_cleanup: &mut bool,
    ) {
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                let name = get_node_text(&func, source).trim().to_string();
                match name.as_str() {
                    "mkstemp" | "MKSTEMP" | "_mkstemp" | "mktemp" | "MKTEMP" | "_wmktemp"
                    | "mkdtemp" | "tmpnam" => {
                        temp_creations.push((
                            node.start_position().row + 1,
                            node.start_position().column + 1,
                        ));
                    }
                    "unlink" | "UNLINK" | "_unlink" | "_wunlink" | "remove" | "DeleteFile"
                    | "DeleteFileA" | "DeleteFileW" => {
                        *has_cleanup = true;
                    }
                    _ => {}
                }
            }
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.scan_temp_file_calls(&child, source, temp_creations, has_cleanup);
            }
        }
    }
}
