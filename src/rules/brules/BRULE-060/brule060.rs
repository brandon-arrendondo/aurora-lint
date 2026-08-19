use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use tree_sitter::Node;

/// Dynamic allocation functions to flag.
const ALLOC_FUNCTIONS: &[&str] = &["malloc", "calloc", "realloc", "free", "aligned_alloc"];

/// Function name suffixes that indicate initialization context.
const INIT_SUFFIXES: &[&str] = &[
    "_init",
    "_setup",
    "_initialize",
    "_create",
    "_new",
    "_alloc",
];

/// Function name prefixes that indicate initialization context.
const INIT_PREFIXES: &[&str] = &["init_", "setup_", "create_", "new_", "alloc_"];

/// Exact function names that are considered initialization context.
const INIT_NAMES: &[&str] = &["main", "init", "setup", "initialize"];

/// BRULE-060: do not use dynamic memory allocation after initialization.
pub struct Brule060;

impl CertRule for Brule060 {
    fn rule_id(&self) -> &'static str {
        "BRULE-060"
    }
    fn description(&self) -> &'static str {
        "Do not use dynamic memory allocation after initialization"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }
    fn cert_id(&self) -> &'static str {
        "BRULE-060"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.walk(node, source, violations);
    }
}

impl Brule060 {
    fn walk(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() == "function_definition" {
            if let Some(func_name) = self.get_function_name(node, source) {
                if !Self::is_init_function(func_name) {
                    if let Some(body) = node.child_by_field_name("body") {
                        self.find_alloc_calls(&body, source, func_name, violations);
                    }
                }
            }
            // Don't recurse into function bodies (already scanned above)
            return;
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.walk(&child, source, violations);
            }
        }
    }

    fn find_alloc_calls(
        &self,
        node: &Node,
        source: &str,
        func_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() == "call_expression" {
            if let Some(callee) = node.child_by_field_name("function") {
                let callee_text = get_node_text(&callee, source);
                if ALLOC_FUNCTIONS.contains(&callee_text) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: format!(
                            "Call to '{}' in non-initialization function '{}'",
                            callee_text, func_name
                        ),
                        file_path: String::new(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        suggestion: Some(
                            "Move dynamic allocation to main() or an initialization function (*_init, *_setup, *_create)"
                                .to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.find_alloc_calls(&child, source, func_name, violations);
            }
        }
    }

    fn get_function_name<'a>(&self, func_def: &Node, source: &'a str) -> Option<&'a str> {
        // function_definition → declarator (function_declarator) → declarator (identifier)
        let declarator = func_def.child_by_field_name("declarator")?;
        self.extract_func_identifier(&declarator, source)
    }

    fn extract_func_identifier<'a>(&self, node: &Node, source: &'a str) -> Option<&'a str> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source));
        }
        // Walk through function_declarator, pointer_declarator wrappers
        if let Some(inner) = node.child_by_field_name("declarator") {
            return self.extract_func_identifier(&inner, source);
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(name) = self.extract_func_identifier(&child, source) {
                    return Some(name);
                }
            }
        }
        None
    }

    fn is_init_function(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();

        if INIT_NAMES.contains(&lower.as_str()) {
            return true;
        }

        for suffix in INIT_SUFFIXES {
            if lower.ends_with(suffix) {
                return true;
            }
        }

        for prefix in INIT_PREFIXES {
            if lower.starts_with(prefix) {
                return true;
            }
        }

        false
    }
}
