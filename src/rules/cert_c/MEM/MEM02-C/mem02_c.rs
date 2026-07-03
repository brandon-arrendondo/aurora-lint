//! MEM02-C: Immediately cast the result of a memory allocation function call into a pointer to the allocated type
//!
//! This rule detects memory allocation calls (malloc, calloc, realloc, aligned_alloc)
//! where the result is not immediately cast to the appropriate pointer type.
//!
//! VIOLATIONS:
//! - malloc/calloc/realloc without a cast
//! - malloc/calloc/realloc cast to wrong type (different from target variable)
//!
//! COMPLIANT:
//! - malloc/calloc/realloc with immediate cast to correct type
//! - Using type-safe allocation macros

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Mem02C;

const ALLOC_FUNCS: &[&str] = &["malloc", "calloc", "realloc", "aligned_alloc"];

impl CertRule for Mem02C {
    fn rule_id(&self) -> &'static str {
        "MEM02-C"
    }

    fn description(&self) -> &'static str {
        "Immediately cast the result of a memory allocation function call into a pointer to the allocated type"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "MEM02-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let mut var_types: HashMap<String, String> = HashMap::new();

        // First pass: collect variable declarations and their types
        self.collect_var_types(node, source, &mut var_types);

        // Second pass: check for violations
        self.check_node(node, source, &mut violations, &var_types);
        violations
    }
}

impl Mem02C {
    fn collect_var_types(
        &self,
        node: &Node,
        source: &str,
        var_types: &mut HashMap<String, String>,
    ) {
        // Look for declarations to track pointer types
        for node in query::find_descendants_of_kind(*node, "declaration") {
            if let Some(decl_type) = self.extract_declaration_type(&node, source) {
                // Get declarators
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if let Some(var_name) =
                            self.extract_var_name_from_declarator(&child, source)
                        {
                            var_types.insert(var_name, decl_type.clone());
                        }
                    }
                }
            }
        }
    }

    fn extract_declaration_type(&self, node: &Node, source: &str) -> Option<String> {
        // Get the type specifier from a declaration
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let kind = child.kind();
                if kind == "type_identifier"
                    || kind == "primitive_type"
                    || kind == "struct_specifier"
                    || kind == "sized_type_specifier"
                {
                    return Some(get_node_text(&child, source).to_string());
                }
            }
        }
        None
    }

    fn extract_var_name_from_declarator(&self, node: &Node, source: &str) -> Option<String> {
        let kind = node.kind();
        if kind == "identifier" {
            return Some(get_node_text(node, source).to_string());
        }
        if kind == "pointer_declarator" || kind == "init_declarator" {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if let Some(name) = self.extract_var_name_from_declarator(&child, source) {
                        return Some(name);
                    }
                }
            }
        }
        None
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, String>,
    ) {
        for node in
            query::find_descendants_of_kinds(*node, &["assignment_expression", "init_declarator"])
        {
            // Check assignment expressions for malloc without cast
            if node.kind() == "assignment_expression" {
                self.check_assignment(&node, source, violations, var_types);
            }

            // Check init_declarator for malloc in declarations
            if node.kind() == "init_declarator" {
                self.check_init_declarator(&node, source, violations, var_types);
            }
        }
    }

    fn check_assignment(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, String>,
    ) {
        let left = match node.child_by_field_name("left") {
            Some(l) => l,
            None => return,
        };
        let right = match node.child_by_field_name("right") {
            Some(r) => r,
            None => return,
        };

        let target_var = get_node_text(&left, source);
        let target_type = var_types.get(target_var);

        // Check if right side is a raw malloc call (no cast)
        if self.is_alloc_call(&right, source) {
            let pos = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::Low,
                message: format!(
                    "Memory allocation result not cast; assign to '{}' without explicit cast",
                    target_var
                ),
                file_path: String::new(),
                line: pos.row + 1,
                column: pos.column + 1,
                suggestion: Some(format!(
                    "Cast the result: ({} *)malloc(...)",
                    target_type.map(|t| t.as_str()).unwrap_or("type")
                )),
                ..Default::default()
            });
            return;
        }

        // Check if right side is a cast expression with wrong type
        if right.kind() == "cast_expression" {
            if let Some(cast_type) = self.get_cast_type(&right, source) {
                // Check if there's an alloc call inside
                if self.contains_alloc_call(&right, source) {
                    // Compare cast type with target variable type
                    if let Some(var_type) = target_type {
                        // Extract base type from pointer (remove * suffix if any in cast)
                        let cast_base = cast_type.trim_end_matches(" *").trim_end_matches('*');
                        if cast_base != var_type
                            && !cast_base.ends_with(var_type)
                            && !var_type.ends_with(cast_base)
                        {
                            let pos = node.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::Low,
                                message: format!(
                                    "Memory allocation cast to '{}' but assigned to '{}' pointer",
                                    cast_type, var_type
                                ),
                                file_path: String::new(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                                suggestion: Some(format!(
                                    "Cast to '({} *)' to match the target variable type",
                                    var_type
                                )),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    fn check_init_declarator(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, String>,
    ) {
        // Get the variable name and initializer
        let mut var_name = None;
        let mut initializer = None;

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "pointer_declarator" || child.kind() == "identifier" {
                    var_name = self.extract_var_name_from_declarator(&child, source);
                }
                if child.kind() == "call_expression" || child.kind() == "cast_expression" {
                    initializer = Some(child);
                }
            }
        }

        if let (Some(name), Some(init)) = (var_name, initializer) {
            let target_type = var_types.get(&name);

            // Check if initializer is raw malloc (no cast)
            if self.is_alloc_call(&init, source) {
                let pos = node.start_position();
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Low,
                    message: format!(
                        "Memory allocation result not cast in initialization of '{}'",
                        name
                    ),
                    file_path: String::new(),
                    line: pos.row + 1,
                    column: pos.column + 1,
                    suggestion: Some(format!(
                        "Cast the result: ({} *)malloc(...)",
                        target_type.map(|t| t.as_str()).unwrap_or("type")
                    )),
                    ..Default::default()
                });
            }
        }
    }

    fn is_alloc_call(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                let func_name = get_node_text(&func, source);
                return ALLOC_FUNCS.contains(&func_name);
            }
        }
        false
    }

    fn contains_alloc_call(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| self.is_alloc_call(&n, source)).is_some()
    }

    fn get_cast_type(&self, node: &Node, source: &str) -> Option<String> {
        // Cast expression has a type_descriptor child
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "type_descriptor" {
                    return Some(get_node_text(&child, source).to_string());
                }
            }
        }
        None
    }
}
