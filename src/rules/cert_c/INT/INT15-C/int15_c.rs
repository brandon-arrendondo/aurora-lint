//! INT15-C: Use intmax_t or uintmax_t for formatted IO on programmer-defined integer types
//!
//! This rule detects formatted I/O operations (printf, scanf) on programmer-defined
//! integer types that don't use intmax_t/uintmax_t for the cast.
//!
//! VIOLATIONS:
//! - printf with typedef'd integer cast to (unsigned) long long instead of (u)intmax_t
//! - scanf with typedef'd integer variable instead of (u)intmax_t temporary
//!
//! COMPLIANT:
//! - printf with cast to uintmax_t and %ju format specifier
//! - scanf with uintmax_t temporary and bounds checking before assignment

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Int15C;

// Formatted I/O functions
const PRINTF_FUNCTIONS: &[&str] = &["printf", "fprintf", "sprintf", "snprintf"];
const SCANF_FUNCTIONS: &[&str] = &["scanf", "fscanf", "sscanf"];

// Risky cast types that may truncate
const RISKY_CAST_TYPES: &[&str] = &[
    "unsigned long long",
    "long long",
    "unsigned long",
    "long",
    "unsigned int",
    "int",
    "unsigned short",
    "short",
];

impl CertRule for Int15C {
    fn rule_id(&self) -> &'static str {
        "INT15-C"
    }

    fn description(&self) -> &'static str {
        "Use intmax_t or uintmax_t for formatted IO on programmer-defined integer types"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "INT15-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let mut typedef_names: HashSet<String> = HashSet::new();
        let mut var_types: HashMap<String, String> = HashMap::new();

        // First pass: collect typedefs and variable types
        self.collect_info(node, source, &mut typedef_names, &mut var_types);

        // Second pass: check for violations
        self.check_violations(node, source, &mut violations, &typedef_names, &var_types);
        violations
    }
}

impl Int15C {
    fn collect_info(
        &self,
        node: &Node,
        source: &str,
        typedef_names: &mut HashSet<String>,
        var_types: &mut HashMap<String, String>,
    ) {
        for n in query::find_descendants_of_kinds(*node, &["type_definition", "declaration"]) {
            if n.kind() == "type_definition" {
                // Collect typedef names
                for i in 0..n.child_count() {
                    if let Some(child) = n.child(i) {
                        if child.kind() == "type_identifier" {
                            let name = get_node_text(&child, source).to_string();
                            typedef_names.insert(name);
                        }
                    }
                }
            } else {
                // Collect variable declarations with typedef types
                if let Some(type_node) = n.child_by_field_name("type") {
                    let type_text = get_node_text(&type_node, source).to_string();
                    // Look for declarators
                    for i in 0..n.child_count() {
                        if let Some(child) = n.child(i) {
                            if child.kind() == "identifier" {
                                let var_name = get_node_text(&child, source).to_string();
                                var_types.insert(var_name, type_text.clone());
                            } else if child.kind() == "init_declarator" {
                                if let Some(decl) = child.child_by_field_name("declarator") {
                                    let var_name = get_node_text(&decl, source).to_string();
                                    var_types.insert(var_name, type_text.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn check_violations(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        typedef_names: &HashSet<String>,
        var_types: &HashMap<String, String>,
    ) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func) = n.child_by_field_name("function") {
                let func_name = get_node_text(&func, source);
                if PRINTF_FUNCTIONS.contains(&func_name) {
                    self.check_printf_call(&n, source, violations, typedef_names);
                } else if SCANF_FUNCTIONS.contains(&func_name) {
                    self.check_scanf_call(&n, source, violations, typedef_names, var_types);
                }
            }
        }
    }

    fn check_printf_call(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        typedef_names: &HashSet<String>,
    ) {
        if let Some(args) = node.child_by_field_name("arguments") {
            // Look for cast expressions in arguments
            for i in 0..args.child_count() {
                if let Some(arg) = args.child(i) {
                    if arg.kind() == "cast_expression" {
                        self.check_printf_cast(&arg, source, violations, typedef_names);
                    }
                }
            }
        }
    }

    fn check_printf_cast(
        &self,
        cast_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        typedef_names: &HashSet<String>,
    ) {
        // Get the type being cast to
        if let Some(type_desc) = cast_node.child_by_field_name("type") {
            let cast_type = get_node_text(&type_desc, source);

            // Check if casting to a risky type (not uintmax_t/intmax_t)
            let is_risky = RISKY_CAST_TYPES.iter().any(|t| cast_type.contains(t));
            let is_safe = cast_type.contains("intmax_t") || cast_type.contains("uintmax_t");

            if is_risky && !is_safe {
                // Check if there are typedefs defined (indicating potential issue)
                if !typedef_names.is_empty() {
                    let pos = cast_node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Programmer-defined integer type cast to '{}' instead of (u)intmax_t for formatted I/O",
                            cast_type
                        ),
                        file_path: String::new(),
                        line: pos.row + 1,
                        column: pos.column + 1,
                        suggestion: Some(
                            "Use (uintmax_t) cast with %ju format specifier, or (intmax_t) with %jd".to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    fn check_scanf_call(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        typedef_names: &HashSet<String>,
        var_types: &HashMap<String, String>,
    ) {
        if let Some(args) = node.child_by_field_name("arguments") {
            // Look for pointer arguments that reference typedef'd variables
            self.check_scanf_args(&args, source, violations, typedef_names, var_types);
        }
    }

    fn check_scanf_args(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        typedef_names: &HashSet<String>,
        var_types: &HashMap<String, String>,
    ) {
        // Look for &identifier pattern where identifier has a typedef type
        if node.kind() == "pointer_expression" || node.kind() == "unary_expression" {
            let text = get_node_text(node, source);
            if text.starts_with('&') {
                // Extract variable name from &x
                let var_name = text.trim_start_matches('&').trim();
                if let Some(var_type) = var_types.get(var_name) {
                    if typedef_names.contains(var_type) {
                        let pos = node.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::High,
                            message: format!(
                                "scanf with programmer-defined type '{}'; use (u)intmax_t temporary with bounds checking",
                                var_type
                            ),
                            file_path: String::new(),
                            line: pos.row + 1,
                            column: pos.column + 1,
                            suggestion: Some(
                                "Read into uintmax_t temporary using strtoumax(), then check bounds before assignment".to_string(),
                            ),
                            ..Default::default()
                        });
                        return;
                    }
                }
            }
        }

        // Recurse into children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_scanf_args(&child, source, violations, typedef_names, var_types);
            }
        }
    }
}
