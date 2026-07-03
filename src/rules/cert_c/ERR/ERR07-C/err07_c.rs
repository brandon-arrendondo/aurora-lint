use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Err07C;

impl CertRule for Err07C {
    fn rule_id(&self) -> &'static str {
        "ERR07-C"
    }

    fn description(&self) -> &'static str {
        "Prefer functions that support error checking over equivalent functions that don't"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ERR07-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Recursively check all function calls in the AST
        check_function_calls(node, source, &mut violations, self.rule_id());

        // CWE-114: check for untrusted input flowing to library-loading functions
        check_tainted_library_loads(node, source, &mut violations);

        violations
    }
}

/// Check all function calls for unsafe functions
fn check_function_calls(
    node: &Node,
    source: &str,
    violations: &mut Vec<RuleViolation>,
    rule_id: &str,
) {
    for call in query::find_descendants_of_kind(*node, "call_expression") {
        check_call_expression(&call, source, violations, rule_id);
    }
}

/// Check a specific call expression for unsafe function usage
fn check_call_expression(
    call_node: &Node,
    source: &str,
    violations: &mut Vec<RuleViolation>,
    rule_id: &str,
) {
    // Get the function name
    if let Some(function) = call_node.child_by_field_name("function") {
        let func_name = ast_utils::get_node_text(&function, source);

        // Check if this is one of the unsafe functions
        if let Some((preferred, reason)) = get_preferred_alternative(&func_name) {
            let pos = call_node.start_position();
            violations.push(RuleViolation {
                rule_id: rule_id.to_string(),
                severity: Severity::Medium,
                message: format!(
                    "Use of '{}' which lacks error checking - prefer '{}'",
                    func_name, preferred
                ),
                file_path: String::new(),
                line: pos.row + 1,
                column: pos.column + 1,
                suggestion: Some(format!(
                    "Replace '{}' with '{}': {}",
                    func_name, preferred, reason
                )),
                ..Default::default()
            });
        }
    }
}

// ── CWE-114: Untrusted input flowing to library-loading functions ────

const TAINT_SOURCES: &[&str] = &[
    "recv", "fgets", "fscanf", "scanf", "read", "getenv", "listen", "connect",
];

const LIBRARY_LOAD_SINKS: &[&str] = &[
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibrary",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "dlopen",
];

fn check_tainted_library_loads(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
    for func in query::find_descendants_of_kind(*node, "function_definition") {
        if let Some(body) = func.child_by_field_name("body") {
            check_function_for_taint_to_library(&body, source, violations);
        }
    }
}

fn check_function_for_taint_to_library(
    body: &Node,
    source: &str,
    violations: &mut Vec<RuleViolation>,
) {
    let mut has_taint = false;
    let mut load_positions: Vec<(String, usize, usize)> = Vec::new();
    scan_taint_and_loads(body, source, &mut has_taint, &mut load_positions);

    if has_taint {
        for (func_name, line, col) in &load_positions {
            violations.push(RuleViolation {
                rule_id: "ERR07-C".to_string(),
                severity: Severity::High,
                message: format!(
                    "{}() called with path from untrusted input — attacker may control which library is loaded",
                    func_name
                ),
                file_path: String::new(),
                line: *line,
                column: *col,
                suggestion: Some(
                    "Use a hard-coded absolute path to a known-good library instead of data from external input"
                        .to_string(),
                ),
                ..Default::default()
            });
        }
    }
}

fn scan_taint_and_loads(
    node: &Node,
    source: &str,
    has_taint: &mut bool,
    load_positions: &mut Vec<(String, usize, usize)>,
) {
    for call in query::find_descendants_of_kind(*node, "call_expression") {
        if let Some(func) = call.child_by_field_name("function") {
            let name = ast_utils::get_node_text(&func, source).trim().to_string();
            if TAINT_SOURCES.contains(&name.as_str()) {
                *has_taint = true;
            }
            if LIBRARY_LOAD_SINKS.contains(&name.as_str()) {
                load_positions.push((
                    name,
                    call.start_position().row + 1,
                    call.start_position().column + 1,
                ));
            }
        }
    }
}

/// Get the preferred alternative for an unsafe function
///
/// Returns: Some((preferred_function, reason)) or None if function is safe
fn get_preferred_alternative(func_name: &str) -> Option<(&'static str, &'static str)> {
    match func_name {
        "atoi" => Some((
            "strtol",
            "strtol provides error indication and prevents undefined behavior on overflow",
        )),
        "atol" => Some((
            "strtol",
            "strtol provides error indication and prevents undefined behavior on overflow",
        )),
        "atoll" => Some((
            "strtoll",
            "strtoll provides error indication and prevents undefined behavior on overflow",
        )),
        "atof" => Some((
            "strtod",
            "strtod provides error indication and prevents undefined behavior on error",
        )),
        "rewind" => Some((
            "fseek",
            "fseek returns a success/failure indication, rewind fails silently",
        )),
        "setbuf" => Some((
            "setvbuf",
            "setvbuf returns an error value if operation fails, setbuf fails silently",
        )),
        "ctime" => Some((
            "asctime/localtime",
            "ctime has undefined behavior if localtime fails",
        )),
        _ => None,
    }
}
