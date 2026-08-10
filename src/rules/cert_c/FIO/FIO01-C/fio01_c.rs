use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Fio01C;

impl CertRule for Fio01C {
    fn rule_id(&self) -> &'static str {
        "FIO01-C"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &'static str {
        "Be careful using functions that use file names for identification"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "FIO01-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Each function gets its own file_name_vars map: a FILE*/fd variable
        // opened in one function and a same-named variable operated on by
        // name in an unrelated function are different objects, so their
        // operation timelines must never be merged. Mirrors the per-function
        // scoping fix applied to EXP39-C/ARR30-C for the same class of bug.
        let functions = query::find_descendants_of_kind(*node, "function_definition");

        if functions.is_empty() {
            // No functions at all (e.g. a declarations/statements-only
            // snippet, as used by this rule's own test fixtures) - fall back
            // to treating the whole translation unit as a single scope,
            // matching pre-fix behavior for this edge case.
            self.check_scope(node, source, &mut violations);
        } else {
            for func in functions {
                self.check_scope(&func, source, &mut violations);
            }
        }

        violations
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct FileOp {
    op_type: FileOpType,
    func_name: String,
    var_name: String,
    line: usize,
    column: usize,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum FileOpType {
    FileOpen,    // fopen
    FileClose,   // fclose
    Remove,      // remove
    Chmod,       // chmod
    Open,        // open (POSIX)
    FdChmod,     // fchmod (safe)
    AccessCheck, // access/stat/lstat — TOCTOU check
    PosixOpen,   // open after check — TOCTOU use
}

impl FileOpType {
    fn name(&self) -> &str {
        match self {
            FileOpType::FileOpen => "fopen",
            FileOpType::FileClose => "fclose",
            FileOpType::Remove => "remove",
            FileOpType::Chmod => "chmod",
            FileOpType::Open => "open",
            FileOpType::FdChmod => "fchmod",
            FileOpType::AccessCheck => "access/stat",
            FileOpType::PosixOpen => "open",
        }
    }
}

impl Fio01C {
    /// Run the TOCTOU detection over a single scope (either one function's
    /// body or, as a fallback, the whole translation unit when there are no
    /// functions) using a file_name_vars map that is fresh to this scope.
    /// Keeping the tracking map scope-local is what prevents two different
    /// functions' same-named FILE*/fd variables from being aggregated into a
    /// single (spurious) TOCTOU finding.
    fn check_scope(&self, scope_node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let mut cursor = scope_node.walk();

        // Track file operations by variable name
        let mut file_name_vars: HashMap<String, Vec<FileOp>> = HashMap::new();
        let mut file_descriptors: Vec<String> = Vec::new();

        // First pass: collect all file operations
        self.collect_file_operations(
            *scope_node,
            source,
            &mut file_name_vars,
            &mut file_descriptors,
            &mut cursor,
        );

        // Second pass: detect TOCTOU vulnerabilities
        for (var_name, operations) in &file_name_vars {
            // Check if the variable is used as a filename with fopen/fclose followed by name-based operations
            let has_file_open = operations
                .iter()
                .any(|op| matches!(op.op_type, FileOpType::FileOpen));
            let has_name_operation = operations
                .iter()
                .any(|op| matches!(op.op_type, FileOpType::Remove | FileOpType::Chmod));

            if has_file_open && has_name_operation {
                // Find the name-based operations
                for op in operations {
                    if matches!(op.op_type, FileOpType::Remove | FileOpType::Chmod) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            message: format!(
                                "TOCTOU vulnerability: file '{}' opened with fopen() then operated on by name with {}(). Use file descriptor operations like fchmod() instead.",
                                var_name,
                                op.op_type.name()
                            ),
                            file_path: String::new(),
                            line: op.line,
                            column: op.column,
                            suggestion: Some("Consider using open() and fchmod()/funlink() instead of fopen() and chmod()/remove()".to_string()),
                            ..Default::default()
                        });
                    }
                }
            }

            // TOCTOU: access()/stat() followed by open()/fopen() on same filename
            let has_access_check = operations
                .iter()
                .any(|op| matches!(op.op_type, FileOpType::AccessCheck));
            let has_posix_open = operations
                .iter()
                .any(|op| matches!(op.op_type, FileOpType::PosixOpen | FileOpType::FileOpen));

            if has_access_check && has_posix_open {
                // Find the check operation for line info
                for op in operations {
                    if matches!(op.op_type, FileOpType::AccessCheck) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            message: format!(
                                "TOCTOU race condition: file '{}' checked with {}() then opened. The file state may change between check and use.",
                                var_name,
                                op.func_name
                            ),
                            file_path: String::new(),
                            line: op.line,
                            column: op.column,
                            suggestion: Some("Open the file directly and check the result instead of checking access/status first.".to_string()),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    fn collect_file_operations<'a>(
        &self,
        node: Node<'a>,
        source: &str,
        file_name_vars: &mut HashMap<String, Vec<FileOp>>,
        _file_descriptors: &mut Vec<String>,
        cursor: &mut tree_sitter::TreeCursor<'a>,
    ) {
        if node.kind() == "call_expression" {
            self.check_call_expression(node, source, file_name_vars);
        }

        // Recurse into children
        if cursor.goto_first_child() {
            loop {
                self.collect_file_operations(
                    cursor.node(),
                    source,
                    file_name_vars,
                    _file_descriptors,
                    cursor,
                );
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
            cursor.goto_parent();
        }
    }

    fn check_call_expression(
        &self,
        node: Node,
        source: &str,
        file_name_vars: &mut HashMap<String, Vec<FileOp>>,
    ) {
        // Get the function being called
        if let Some(function_node) = node.child_by_field_name("function") {
            let func_name = get_node_text(&function_node, source);

            // Get the arguments
            if let Some(args_node) = node.child_by_field_name("arguments") {
                let op_type = match func_name {
                    "fopen" => Some(FileOpType::FileOpen),
                    "remove" => Some(FileOpType::Remove),
                    "chmod" => Some(FileOpType::Chmod),
                    "fclose" => Some(FileOpType::FileClose),
                    // TOCTOU check functions (including Juliet macros)
                    "access" | "ACCESS" | "_access" => Some(FileOpType::AccessCheck),
                    "stat" | "STAT" | "_stat" | "lstat" => Some(FileOpType::AccessCheck),
                    // TOCTOU use functions
                    "open" | "OPEN" | "_open" => Some(FileOpType::PosixOpen),
                    _ => None,
                };

                if let Some(op_type) = op_type {
                    if let Some(first_arg) = args_node.child(1) {
                        if first_arg.kind() == "identifier" {
                            let var_name = get_node_text(&first_arg, source);
                            let op = FileOp {
                                op_type,
                                func_name: func_name.to_string(),
                                var_name: var_name.to_string(),
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                            };
                            file_name_vars
                                .entry(var_name.to_string())
                                .or_default()
                                .push(op);
                        }
                    }
                }
            }
        }
    }
}
