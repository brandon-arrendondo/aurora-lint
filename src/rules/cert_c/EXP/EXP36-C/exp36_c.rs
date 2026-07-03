use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Exp36C;

impl CertRule for Exp36C {
    fn rule_id(&self) -> &'static str {
        "EXP36-C"
    }

    fn description(&self) -> &'static str {
        "Do not cast pointers into more strictly aligned pointer types"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "EXP36-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        for descendant in
            query::find_descendants_of_kinds(*node, &["cast_expression", "init_declarator"])
        {
            match descendant.kind() {
                // Pattern 1: Direct casts - (int *)&c or (struct foo *)data
                "cast_expression" => {
                    self.check_cast_expression(&descendant, source, &mut violations);
                }
                // Pattern 2: Init declarators with function calls returning void* from less-aligned types
                "init_declarator" => {
                    self.check_init_declarator(&descendant, source, &mut violations);
                }
                _ => {}
            }
        }

        violations
    }
}

impl Exp36C {
    /// Check cast expressions for alignment violations
    fn check_cast_expression(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get the type being cast to
        if let Some(type_node) = node.child_by_field_name("type") {
            let target_type = ast_utils::get_node_text(&type_node, source).trim();

            // EXP36-C is about pointer-to-pointer casts — skip non-pointer target types
            // e.g., (unsigned)time(NULL) is an integer cast, not a pointer alignment issue
            if !target_type.contains('*') {
                return;
            }

            let target_alignment = self.get_type_alignment(target_type);

            // Get the value being cast
            if let Some(value_node) = node.child_by_field_name("value") {
                let source_type = self.infer_pointer_type(&value_node, source);

                // Skip if source is not actually a pointer type
                if source_type == "unknown *" {
                    return;
                }

                let source_alignment = self.get_type_alignment(&source_type);

                // Check if we're casting to a more strictly aligned type
                if target_alignment > source_alignment && source_alignment > 0 {
                    let start_point = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: "EXP36-C".to_string(),
                        severity: Severity::Low,
                        message: format!(
                            "Casting from {} (alignment {}) to {} (alignment {}) may cause alignment issues",
                            source_type, source_alignment, target_type, target_alignment
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Use memcpy or ensure proper alignment before casting".to_string()
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Check init declarators for indirect casts through void*
    /// Pattern: int *int_ptr = loop_function(char_ptr);
    /// where loop_function takes void* and returns void*/int*
    fn check_init_declarator(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get the declarator type
        if let Some(declarator) = node.child_by_field_name("declarator") {
            let var_type = self.extract_pointer_type_from_declarator(&declarator, source);

            // Get the value being assigned (often a function call)
            if let Some(value) = node.child_by_field_name("value") {
                if value.kind() == "call_expression" {
                    // Check if the function returns void* and the argument is a less-aligned type
                    self.check_void_pointer_conversion(&value, &var_type, source, violations);
                }
            }
        }
    }

    /// Check for conversions through void* that increase alignment
    fn check_void_pointer_conversion(
        &self,
        call_node: &Node,
        target_type: &str,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let target_alignment = self.get_type_alignment(target_type);

        // Get the function arguments
        if let Some(arguments) = call_node.child_by_field_name("arguments") {
            for i in 0..arguments.child_count() {
                if let Some(arg) = arguments.child(i) {
                    if arg.kind() == "identifier" || arg.kind() == "pointer_expression" {
                        let arg_type = self.infer_pointer_type(&arg, source);
                        let arg_alignment = self.get_type_alignment(&arg_type);

                        // Only flag if we can definitively determine the argument is less-aligned
                        // Skip "unknown *" types to avoid false positives
                        if arg_type != "unknown *"
                            && target_alignment > arg_alignment
                            && arg_alignment > 0
                            && arg_alignment < 4
                        {
                            let start_point = call_node.start_position();
                            violations.push(RuleViolation {
                                rule_id: "EXP36-C".to_string(),
                                severity: Severity::Low,
                                message: format!(
                                    "Potential alignment violation: passing {} (alignment {}) through function to {} (alignment {})",
                                    arg_type, arg_alignment, target_type, target_alignment
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some(
                                    "Ensure function maintains proper pointer alignment or use properly aligned intermediate objects".to_string()
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    /// Extract pointer type from declarator
    fn extract_pointer_type_from_declarator(&self, declarator: &Node, source: &str) -> String {
        // Walk up the tree to find the type
        if let Some(parent) = declarator.parent() {
            if parent.kind() == "init_declarator" {
                if let Some(grandparent) = parent.parent() {
                    if grandparent.kind() == "declaration" {
                        // Get type from declaration
                        for i in 0..grandparent.child_count() {
                            if let Some(child) = grandparent.child(i) {
                                if child.kind() == "type_descriptor"
                                    || child.kind() == "primitive_type"
                                    || child.kind() == "struct_specifier"
                                    || child.kind() == "sized_type_specifier"
                                {
                                    let type_text = ast_utils::get_node_text(&child, source);
                                    // Check if declarator has pointer_declarator
                                    if self.has_pointer_declarator(declarator) {
                                        return format!("{} *", type_text.trim());
                                    }
                                    return type_text.trim().to_string();
                                }
                            }
                        }
                    }
                }
            }
        }
        String::from("unknown")
    }

    /// Check if a declarator is a pointer declarator
    fn has_pointer_declarator(&self, node: &Node) -> bool {
        if node.kind() == "pointer_declarator" {
            return true;
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if self.has_pointer_declarator(&child) {
                    return true;
                }
            }
        }
        false
    }

    /// Infer the pointer type from a node (for expressions like &c, char_ptr, etc.)
    fn infer_pointer_type(&self, node: &Node, source: &str) -> String {
        match node.kind() {
            "parenthesized_expression" => {
                // Unwrap parentheses: (data + offset) -> data + offset
                if let Some(inner) = node.child(1) {
                    return self.infer_pointer_type(&inner, source);
                }
                "unknown *".to_string()
            }
            "pointer_expression" => {
                // Pattern: &c where c is char
                // Get the argument and infer its type
                if let Some(arg) = node.child_by_field_name("argument") {
                    let arg_text = ast_utils::get_node_text(&arg, source);
                    // Simple heuristic: if variable name suggests type
                    if arg_text.contains("char") || arg_text == "c" {
                        return "char *".to_string();
                    }
                }
                "unknown *".to_string()
            }
            "identifier" => {
                let id_text = ast_utils::get_node_text(node, source);
                // Heuristic based on variable names
                if id_text.contains("char")
                    || id_text.ends_with("_ptr") && id_text.starts_with("char")
                {
                    "char *".to_string()
                } else if id_text.contains("int") {
                    "int *".to_string()
                } else if id_text.contains("data") {
                    // Common pattern for char buffers
                    "char *".to_string()
                } else {
                    "unknown *".to_string()
                }
            }
            "binary_expression" => {
                // Pattern: data + offset
                if let Some(left) = node.child_by_field_name("left") {
                    return self.infer_pointer_type(&left, source);
                }
                "char *".to_string() // Common pattern for pointer arithmetic
            }
            _ => "unknown *".to_string(),
        }
    }

    /// Get alignment requirements for a type
    /// Returns alignment in bytes
    fn get_type_alignment(&self, type_str: &str) -> usize {
        // Create a map of types to alignments
        let alignments: HashMap<&str, usize> = [
            ("char", 1),
            ("char *", 1),
            ("unsigned char", 1),
            ("unsigned char *", 1),
            ("signed char", 1),
            ("signed char *", 1),
            // Fixed-width byte types — alignment 1 (same as char)
            ("uint8_t", 1),
            ("uint8_t *", 1),
            ("int8_t", 1),
            ("int8_t *", 1),
            ("short", 2),
            ("short *", 2),
            ("unsigned short", 2),
            ("int", 4),
            ("int *", 4),
            ("unsigned int", 4),
            ("unsigned", 4),
            ("long", 4), // Platform dependent, conservative estimate
            ("unsigned long", 4),
            ("long long", 8),
            ("unsigned long long", 8),
            ("float", 4),
            ("float *", 4),
            ("double", 8),
            ("double *", 8),
            ("long double", 16),
            ("void *", 1), // void* itself has no alignment, use 1
            ("unknown *", 1),
        ]
        .iter()
        .cloned()
        .collect();

        let normalized = type_str.trim();

        // Check for exact match
        if let Some(&alignment) = alignments.get(normalized) {
            return alignment;
        }

        // Check for struct types (typically at least 4-byte aligned)
        if normalized.starts_with("struct ") {
            return 4; // Conservative estimate for struct alignment
        }

        // For pointer types not in map, assume 4-byte alignment
        if normalized.ends_with("*") {
            return 4;
        }

        // Unknown types - return 0 to avoid false positives
        0
    }
}
