//! EXP11-C: Do not make assumptions regarding the layout of structures with bit-fields
//!
//! Bit-field members in structures have implementation-defined layout. Making assumptions
//! about this layout (e.g., via pointer arithmetic or casts) leads to non-portable code.
//!
//! ## Examples:
//!
//! **Non-compliant (casting bit-field struct to pointer):**
//! ```c
//! struct bf {
//!     unsigned int m1 : 6;
//!     unsigned int m2 : 4;
//! };
//!
//! void function() {
//!     unsigned char *ptr;
//!     struct bf data;
//!     ptr = (unsigned char *)&data;
//!     ptr++;
//!     *ptr += 1;  // Violates EXP11-C - assumes layout
//! }
//! ```
//!
//! **Compliant (direct bit-field access):**
//! ```c
//! struct bf {
//!     unsigned int m1 : 6;
//!     unsigned int m2 : 4;
//! };
//!
//! void function() {
//!     struct bf data;
//!     data.m1 = 0;
//!     data.m2 += 1;  // Direct access is safe
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Pass 1: Identify structs that contain bit-field members
//! - Pass 2: Track variables declared with bit-field struct types
//! - Pass 3: Detect casts from bit-field struct pointers to char*/unsigned char*

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Exp11C;

impl CertRule for Exp11C {
    fn rule_id(&self) -> &'static str {
        "EXP11-C"
    }

    fn description(&self) -> &'static str {
        "Do not make assumptions regarding the layout of structures with bit-fields"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "EXP11-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Only check at translation unit level (root)
        if node.kind() != "translation_unit" {
            return violations;
        }

        // Pass 1: Collect all struct names that have bit-fields
        let bitfield_structs = collect_bitfield_structs(node, source);

        // Pass 2: Collect all variable names that are of bit-field struct types
        let bitfield_vars = collect_bitfield_variables(node, source, &bitfield_structs);

        // Pass 3: Find casts of bit-field struct addresses to pointers
        find_bitfield_pointer_casts(node, source, &bitfield_vars, &mut violations);

        violations
    }
}

/// Collects names of all structs that contain bit-field members
fn collect_bitfield_structs<'a>(root: &Node, source: &'a str) -> HashSet<&'a str> {
    let mut bitfield_structs = HashSet::new();

    for node in query::find_descendants_of_kind(*root, "struct_specifier") {
        // Check if struct has bit-fields in body
        if let Some(body) = node.child_by_field_name("body") {
            if contains_bitfield(&body) {
                // Extract struct name if present
                if let Some(name_node) = node.child_by_field_name("name") {
                    let struct_name = ast_utils::get_node_text(&name_node, source);
                    bitfield_structs.insert(struct_name);
                }
            }
        }
    }

    bitfield_structs
}

/// Checks if a struct body contains bit-field declarations
fn contains_bitfield(body: &Node) -> bool {
    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if child.kind() == "field_declaration" {
            // Look for bitfield_clause child
            let mut field_cursor = child.walk();
            for field_child in child.children(&mut field_cursor) {
                if field_child.kind() == "bitfield_clause" {
                    return true;
                }
            }
        }
    }
    false
}

/// Collects names of all variables declared with bit-field struct types
fn collect_bitfield_variables<'a>(
    root: &Node,
    source: &'a str,
    bitfield_structs: &HashSet<&'a str>,
) -> HashSet<&'a str> {
    let mut bitfield_vars = HashSet::new();

    for node in query::find_descendants_of_kind(*root, "declaration") {
        // Check if this is a struct type declaration
        if let Some(type_node) = node.child_by_field_name("type") {
            let type_text = ast_utils::get_node_text(&type_node, source);

            // Extract struct name from "struct bf" type text
            if let Some(struct_name) = ast_utils::extract_struct_name_from_type(&type_text) {
                // Check if this struct has bit-fields
                if bitfield_structs.contains(struct_name) {
                    // Extract variable names from declarators
                    extract_declared_variable_names(&node, source, &mut bitfield_vars);
                }
            }
        }
    }

    bitfield_vars
}

/// Extracts struct name from type text like "struct bf"
/// Extracts variable names from declarators in a declaration
fn extract_declared_variable_names<'a>(
    decl_node: &Node,
    source: &'a str,
    var_names: &mut HashSet<&'a str>,
) {
    let mut cursor = decl_node.walk();
    for child in decl_node.children(&mut cursor) {
        match child.kind() {
            "init_declarator" => {
                // Declaration with initialization: int x = 5;
                if let Some(declarator) = child.child_by_field_name("declarator") {
                    if let Some(name) = extract_identifier_from_declarator(&declarator, source) {
                        var_names.insert(name);
                    }
                }
            }
            "identifier" | "pointer_declarator" | "array_declarator" => {
                // Plain declaration: struct bf data;
                if let Some(name) = extract_identifier_from_declarator(&child, source) {
                    var_names.insert(name);
                }
            }
            _ => {}
        }
    }
}

/// Extracts identifier name from a declarator node
fn extract_identifier_from_declarator<'a>(declarator: &Node, source: &'a str) -> Option<&'a str> {
    match declarator.kind() {
        "identifier" => Some(ast_utils::get_node_text(declarator, source)),
        "pointer_declarator" | "array_declarator" => {
            if let Some(child_declarator) = declarator.child_by_field_name("declarator") {
                extract_identifier_from_declarator(&child_declarator, source)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Finds casts of bit-field struct addresses to pointer types
fn find_bitfield_pointer_casts(
    node: &Node,
    source: &str,
    bitfield_vars: &HashSet<&str>,
    violations: &mut Vec<RuleViolation>,
) {
    for cast_node in query::find_descendants_of_kind(*node, "cast_expression") {
        check_cast_expression(&cast_node, source, bitfield_vars, violations);
    }
}

/// Checks if a cast expression casts a bit-field struct address to a pointer
fn check_cast_expression(
    node: &Node,
    source: &str,
    bitfield_vars: &HashSet<&str>,
    violations: &mut Vec<RuleViolation>,
) {
    // Get the type being cast to
    if let Some(type_node) = node.child_by_field_name("type") {
        let type_text = ast_utils::get_node_text(&type_node, source);

        // Check if casting to char* or unsigned char*
        if is_char_pointer_type(&type_text) {
            // Get the value being cast
            if let Some(value_node) = node.child_by_field_name("value") {
                // Check if it's an address-of expression on a bitfield struct variable
                if let Some(var_name) = extract_address_of_variable(&value_node, source) {
                    if bitfield_vars.contains(var_name) {
                        let start_point = node.start_position();
                        violations.push(RuleViolation {
                            rule_id: "EXP11-C".to_string(),
                            severity: Severity::Medium,
                            message: format!(
                                "Casting address of bit-field structure '{}' to pointer type makes assumptions about bit-field layout. Bit-field layout is implementation-defined.",
                                var_name
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Access bit-fields directly through structure members instead of pointer arithmetic".to_string()
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }
}

/// Checks if type is char* or unsigned char*
fn is_char_pointer_type(type_text: &str) -> bool {
    let normalized = type_text.replace(' ', "");
    normalized.contains("char*") || normalized.contains("unsignedchar*")
}

/// Extracts variable name from address-of expression (&var)
fn extract_address_of_variable<'a>(node: &Node, source: &'a str) -> Option<&'a str> {
    // Check for & (address-of) operator - represented as pointer_expression in tree-sitter
    if node.kind() == "pointer_expression" {
        // Check for & operator
        let mut cursor = node.walk();
        let mut has_ampersand = false;
        for child in node.children(&mut cursor) {
            if child.kind() == "&" {
                has_ampersand = true;
                break;
            }
        }

        if has_ampersand {
            // Extract the variable being addressed
            if let Some(argument) = node.child_by_field_name("argument") {
                if argument.kind() == "identifier" {
                    return Some(ast_utils::get_node_text(&argument, source));
                }
            }
        }
    }
    None
}
