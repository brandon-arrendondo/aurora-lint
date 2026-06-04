// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Ryan Bissell

//! DCL05-C: Use typedefs of non-pointer types only
//!
//! This rule detects typedefs that define pointer types, which can lead to
//! confusion about const-qualification and make code harder to understand.
//!
//! Violations:
//! - typedef int *IntPtr;  // typedef of a pointer type
//!
//! Compliant:
//! - typedef int Integer;  // typedef of non-pointer type
//! - Integer *ptr;         // pointer declared explicitly
//!
//! References:
//! - https://wiki.sei.cmu.edu/confluence/display/c/DCL05-C.+Use+typedefs+of+non-pointer+types+only

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use tree_sitter::Node;

pub struct Dcl05C;

impl CertRule for Dcl05C {
    fn rule_id(&self) -> &'static str {
        "DCL05-C"
    }

    fn description(&self) -> &'static str {
        "Use typedefs of non-pointer types only"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "DCL05-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First pass: collect all pointer typedefs defined in this file
        let mut pointer_typedefs = std::collections::HashSet::new();
        collect_pointer_typedefs(node, source, &mut pointer_typedefs);

        // Check typedef declarations
        check_typedef_declarations(node, source, &mut violations);

        // Check for usage of external pointer typedefs (from headers)
        check_external_pointer_typedef_usage(node, source, &mut violations, &pointer_typedefs);

        // Check complex function pointers
        check_complex_function_pointers(node, source, &mut violations);

        violations
    }
}

/// Collect all pointer typedefs defined in the file (for tracking)
fn collect_pointer_typedefs(
    node: &Node,
    source: &str,
    pointer_typedefs: &mut std::collections::HashSet<String>,
) {
    if node.kind() == "type_definition" {
        // Check if this typedef defines a pointer type (including const pointer typedefs)
        if contains_pointer_declarator(node) {
            if let Some(typedef_name) = extract_typedef_name(node, source) {
                pointer_typedefs.insert(typedef_name);
            }
        }
    }

    // Recurse through children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_pointer_typedefs(&child, source, pointer_typedefs);
    }
}

/// Check for typedef declarations that define pointer types (without const)
fn check_typedef_declarations(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
    if node.kind() == "type_definition" {
        // Check if this typedef defines a pointer type
        if is_pointer_typedef(node, source) {
            // Check if it's a const pointer typedef (allowed)
            if is_const_pointer_typedef(node, source) {
                // Compliant: typedef const TYPE *NAME is allowed
                return;
            }

            // Extract the typedef name for better error message
            let typedef_name =
                extract_typedef_name(node, source).unwrap_or_else(|| "unknown".to_string());

            violations.push(RuleViolation {
                rule_id: "DCL05-C".to_string(),
                file_path: "".to_string(),
                message: format!(
                    "Typedef '{}' defines a pointer type, which can cause confusion with const-qualification",
                    typedef_name
                ),
                line: node.start_position().row + 1,
                column: node.start_position().column,
                severity: Severity::Medium,
                suggestion: Some("Use typedef of non-pointer type and declare pointers explicitly at point of use".to_string()),
                requires_manual_review: Some(false),
            });
        }
    }

    // Recurse through children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        check_typedef_declarations(&child, source, violations);
    }
}

/// Check if a type_definition node defines a pointer type
fn is_pointer_typedef(node: &Node, _source: &str) -> bool {
    // Look for pointer_declarator in the typedef
    contains_pointer_declarator(node)
}

/// Recursively check if node tree contains a pointer_declarator
fn contains_pointer_declarator(node: &Node) -> bool {
    if node.kind() == "pointer_declarator" {
        return true;
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if contains_pointer_declarator(&child) {
            return true;
        }
    }
    false
}

/// Extract the typedef name from a type_definition node
fn extract_typedef_name(node: &Node, source: &str) -> Option<String> {
    // The typedef name is usually in a type_identifier node
    find_type_identifier(node, source)
}

/// Recursively find a type_identifier node
fn find_type_identifier(node: &Node, source: &str) -> Option<String> {
    if node.kind() == "type_identifier" {
        return Some(get_node_text(node, source).to_string());
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(id) = find_type_identifier(&child, source) {
            return Some(id);
        }
    }
    None
}

/// Check if a typedef is a const pointer typedef (allowed by DCL05-C)
/// Example: typedef const TYPE *NAME;
fn is_const_pointer_typedef(node: &Node, source: &str) -> bool {
    // Get the full text of the typedef
    let typedef_text = get_node_text(node, source);

    // Check for "const" before the pointer
    // Pattern: typedef const TYPE *NAME; or typedef TYPE const *NAME;
    // Look for "const" keyword followed by pointer syntax
    let has_const = typedef_text.contains("const");

    // Check if const appears before the * in a pointer typedef
    if !has_const {
        return false;
    }

    // Simple pattern match: const should appear before * in the typedef
    // This handles: typedef const TYPE *NAME;
    if let Some(const_pos) = typedef_text.find("const") {
        if let Some(star_pos) = typedef_text.find('*') {
            // const should come before * for it to be a pointer-to-const
            return const_pos < star_pos;
        }
    }

    false
}

/// Check for usage of external pointer typedefs (from headers like Windows.h)
/// These are pointer typedefs that are used but not defined in the current file
fn check_external_pointer_typedef_usage(
    node: &Node,
    source: &str,
    violations: &mut Vec<RuleViolation>,
    defined_typedefs: &std::collections::HashSet<String>,
) {
    // Look for parameter declarations or variable declarations that use type identifiers
    if node.kind() == "parameter_declaration" || node.kind() == "declaration" {
        // Find type_identifier nodes in parameters/declarations
        if let Some(type_id_node) = find_first_type_identifier_node(node) {
            let type_name = get_node_text(&type_id_node, source);

            // Check if this looks like a Windows-style pointer typedef (ends with P or LP prefix)
            // Common patterns: LPPOINT, LPTSTR, PLONG, etc.
            if is_likely_external_pointer_typedef(&type_name)
                && !defined_typedefs.contains(type_name)
            {
                // This is likely an external pointer typedef being used
                violations.push(RuleViolation {
                    rule_id: "DCL05-C".to_string(),
                    file_path: "".to_string(),
                    message: format!(
                        "Usage of external pointer typedef '{}' (likely from header). \
                        Pointer typedefs can cause confusion with const-qualification",
                        type_name
                    ),
                    line: type_id_node.start_position().row + 1,
                    column: type_id_node.start_position().column,
                    severity: Severity::Medium,
                    suggestion: Some(
                        "Avoid using pointer typedefs from external headers, or use const-qualified versions".to_string()
                    ),
                    requires_manual_review: Some(false),
                });
            }
        }
    }

    // Recurse through children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        check_external_pointer_typedef_usage(&child, source, violations, defined_typedefs);
    }
}

/// Find the first type_identifier node (non-recursive, just direct children)
#[allow(clippy::manual_find)]
fn find_first_type_identifier_node<'a>(node: &'a Node) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "type_identifier" {
            return Some(child);
        }
    }
    None
}

/// Check if a type name looks like an external pointer typedef
/// Common patterns: LP* (long pointer), P* (pointer), *PTR, etc.
fn is_likely_external_pointer_typedef(type_name: &str) -> bool {
    // Windows API patterns
    if type_name.starts_with("LP") && type_name.len() > 2 {
        // LPPOINT, LPTSTR, etc. but NOT LPCPOINT (const version is OK)
        return !type_name.starts_with("LPC");
    }

    // P-prefix patterns (PLONG, PDWORD, etc.)
    if type_name.starts_with('P')
        && type_name.len() > 1
        && type_name.chars().nth(1).unwrap().is_uppercase()
    {
        return true;
    }

    // PTR suffix patterns
    if type_name.ends_with("PTR") || type_name.ends_with("Ptr") {
        return true;
    }

    false
}

/// Check for complex function pointer declarations without typedef
fn check_complex_function_pointers(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
    // Look for function declarations with complex function pointer parameters or return types
    if node.kind() == "function_declarator" || node.kind() == "declaration" {
        let text = get_node_text(node, source);

        // Detect complex function pointer syntax: contains (* and multiple parentheses
        if is_complex_function_pointer_syntax(&text) {
            violations.push(RuleViolation {
                rule_id: "DCL05-C".to_string(),
                file_path: "".to_string(),
                message: "Complex function pointer declaration should use typedef for clarity"
                    .to_string(),
                line: node.start_position().row + 1,
                column: node.start_position().column,
                severity: Severity::Medium,
                suggestion: Some(
                    "Use typedef to simplify complex function pointer declarations".to_string(),
                ),
                requires_manual_review: Some(false),
            });
        }
    }

    // Recurse through children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        check_complex_function_pointers(&child, source, violations);
    }
}

/// Check if text contains complex function pointer syntax
fn is_complex_function_pointer_syntax(text: &str) -> bool {
    // Complex function pointer has pattern like: void (*signal(int, void (*)(int)))(int);
    // Look for (*...)(  pattern which indicates function pointer return type
    let has_func_ptr_return = text.contains("(*") && text.matches('(').count() >= 3;

    // Also check for function pointers in parameter lists without typedef
    // Pattern: void (*)(int) - unnamed function pointer parameter
    let has_unnamed_func_ptr = text.contains("(*)(");

    has_func_ptr_return || has_unnamed_func_ptr
}
