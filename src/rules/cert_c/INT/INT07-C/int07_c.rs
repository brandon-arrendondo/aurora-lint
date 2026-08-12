//! INT07-C: Use only explicitly signed or unsigned char type for numeric values
//!
//! The plain `char` type has implementation-defined signedness, making it unsuitable
//! for numeric operations. Use explicit `signed char` or `unsigned char` for numeric values.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! char c = 200;
//! int i = 1000;
//! printf("i/c = %d\n", i/c);  // Unpredictable: 5 (unsigned) or -17 (signed)
//! ```
//!
//! **Compliant:**
//! ```c
//! unsigned char c = 200;
//! int i = 1000;
//! printf("i/c = %d\n", i/c);  // Predictable: 5
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Int07C;

impl CertRule for Int07C {
    fn rule_id(&self) -> &'static str {
        "INT07-C"
    }

    fn description(&self) -> &'static str {
        "Use only explicitly signed or unsigned char type for numeric values"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "INT07-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Variable name -> declared-type lookup must stay scoped to a
        // single function: two unrelated functions in the same file
        // commonly reuse a local name (e.g. `ret`, `pos`) with different
        // types, and a file-wide map would misattribute one function's
        // char-typed variable onto the other's identically-named
        // int/pointer variable (task 394). File-scope (global) plain-char
        // declarations are collected separately, without descending into
        // any function body, and are visible to every function as well as
        // to file-scope code itself (e.g. the CERT wiki example, which
        // declares and uses `char c` outside any function).
        let mut global_decls = Vec::new();
        collect_outside_functions(*node, "declaration", &mut global_decls);
        let mut global_vars: HashMap<String, (usize, usize)> = HashMap::new();
        for decl in &global_decls {
            self.find_plain_char_vars(decl, source, &mut global_vars);
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() != "function_definition" {
                    self.find_numeric_uses(&child, source, &global_vars, &mut violations);
                }
            }
        }

        for func in query::find_descendants_of_kind(*node, "function_definition") {
            let mut plain_char_vars = global_vars.clone();
            self.find_plain_char_vars(&func, source, &mut plain_char_vars);
            self.find_numeric_uses(&func, source, &plain_char_vars, &mut violations);
        }

        violations
    }
}

/// Collect descendants of `kind` that lie outside every function body —
/// i.e. true file/global scope, possibly nested under preprocessor
/// conditionals but never inside a `function_definition`.
fn collect_outside_functions<'a>(node: Node<'a>, kind: &str, out: &mut Vec<Node<'a>>) {
    if node.kind() == "function_definition" {
        return;
    }
    if node.kind() == kind {
        out.push(node);
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_outside_functions(child, kind, out);
        }
    }
}

impl Int07C {
    /// Find plain char variable declarations (not signed char or unsigned char)
    fn find_plain_char_vars(
        &self,
        node: &Node,
        source: &str,
        plain_char_vars: &mut HashMap<String, (usize, usize)>,
    ) {
        for n in query::find_descendants_of_kinds(*node, &["declaration", "parameter_declaration"])
        {
            let decl_text = get_node_text(&n, source);

            // Check if this is a char declaration (not signed char or unsigned char)
            // Skip char* pointers and char[] arrays — INT07-C is about char VALUE signedness,
            // not pointer arithmetic on char*.
            if self.is_plain_char_declaration(&decl_text)
                && !self.is_pointer_or_array_declaration(&n)
            {
                let var_name = if n.kind() == "declaration" {
                    self.extract_var_name(&n, source)
                } else {
                    self.extract_param_name(&n, source)
                };
                if let Some(var_name) = var_name {
                    plain_char_vars.insert(
                        var_name,
                        (n.start_position().row + 1, n.start_position().column + 1),
                    );
                }
            }
        }
    }

    /// Check if a declaration/parameter contains a pointer or array declarator.
    /// Used to skip `char *pos` and `char buf[N]` — only flag plain `char c` values.
    fn is_pointer_or_array_declaration(&self, node: &Node) -> bool {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "pointer_declarator" | "array_declarator" => return true,
                    "init_declarator" => {
                        for j in 0..child.child_count() {
                            if let Some(grandchild) = child.child(j) {
                                if grandchild.kind() == "pointer_declarator"
                                    || grandchild.kind() == "array_declarator"
                                {
                                    return true;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        false
    }

    /// Check if declaration text represents a plain char (not signed/unsigned char)
    fn is_plain_char_declaration(&self, decl_text: &str) -> bool {
        // Must contain "char"
        if !decl_text.contains("char") {
            return false;
        }

        // Must NOT contain "signed" or "unsigned" before "char"
        if decl_text.contains("signed") || decl_text.contains("unsigned") {
            return false;
        }

        // Check for patterns like "char x" or "char *x"
        // Avoid false positives like "character" or variable names containing "char"
        let normalized = decl_text.replace('\t', " ");
        let patterns = [
            " char ", " char*", " char[", "\tchar ", "\tchar*", "\tchar[",
        ];

        // Also check if it starts with "char " (at beginning of declaration)
        if normalized.trim().starts_with("char ") || normalized.trim().starts_with("char*") {
            return true;
        }

        patterns.iter().any(|p| normalized.contains(p))
    }

    /// Find uses of plain char variables in numeric contexts
    fn find_numeric_uses(
        &self,
        node: &Node,
        source: &str,
        plain_char_vars: &HashMap<String, (usize, usize)>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kinds(
            *node,
            &[
                "binary_expression",
                "assignment_expression",
                "unary_expression",
                "update_expression",
            ],
        ) {
            // Check binary expressions (arithmetic and comparison)
            if n.kind() == "binary_expression" {
                if let Some(operator) = n.child_by_field_name("operator") {
                    let op_text = get_node_text(&operator, source);

                    // Arithmetic operators only: +, -, *, /, %
                    // Comparisons (<, <=, >, >=, ==, !=) are intentionally excluded:
                    // patterns like `data < CHAR_MAX` are the CORRECT safe-coding pattern
                    // for range-checking plain char variables before arithmetic.
                    let is_numeric_op = matches!(op_text, "+" | "-" | "*" | "/" | "%");

                    if is_numeric_op {
                        // Check left and right operands
                        if let Some(left) = n.child_by_field_name("left") {
                            self.check_operand_for_violation(
                                &left,
                                source,
                                plain_char_vars,
                                violations,
                            );
                        }
                        if let Some(right) = n.child_by_field_name("right") {
                            self.check_operand_for_violation(
                                &right,
                                source,
                                plain_char_vars,
                                violations,
                            );
                        }
                    }
                }
            } else if n.kind() == "assignment_expression" {
                // Check assignment expressions with numeric values
                if let Some(right) = n.child_by_field_name("right") {
                    // If right side is a numeric literal, check left side
                    if self.is_numeric_literal(&right, source) {
                        if let Some(left) = n.child_by_field_name("left") {
                            self.check_operand_for_violation(
                                &left,
                                source,
                                plain_char_vars,
                                violations,
                            );
                        }
                    }
                }
            } else {
                // Check unary operations (++, --, unary -, unary +)
                if let Some(argument) = n.child_by_field_name("argument") {
                    self.check_operand_for_violation(
                        &argument,
                        source,
                        plain_char_vars,
                        violations,
                    );
                }
            }
        }
    }

    /// Check if an operand is a plain char variable and report violation
    fn check_operand_for_violation(
        &self,
        operand: &Node,
        source: &str,
        plain_char_vars: &HashMap<String, (usize, usize)>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let operand_text = get_node_text(operand, source);

        // Check if this operand is a plain char variable
        if plain_char_vars.contains_key(operand_text) {
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                message: format!(
                    "Variable '{}' of type char used in numeric operation. \
                     Use explicit 'signed char' or 'unsigned char' for numeric values.",
                    operand_text
                ),
                severity: self.severity(),
                line: operand.start_position().row + 1,
                column: operand.start_position().column + 1,
                file_path: String::new(),
                suggestion: Some(format!(
                    "Change declaration of '{}' from 'char' to 'signed char' or 'unsigned char'",
                    operand_text
                )),
                requires_manual_review: None,
            });
        }

        // Also check if operand itself is an identifier
        if operand.kind() == "identifier" {
            // Already handled above
        } else {
            // Recursively check children (for complex expressions)
            for i in 0..operand.child_count() {
                if let Some(child) = operand.child(i) {
                    if child.kind() == "identifier" {
                        let child_text = get_node_text(&child, source);
                        if plain_char_vars.contains_key(child_text) {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                message: format!(
                                    "Variable '{}' of type char used in numeric operation. \
                                     Use explicit 'signed char' or 'unsigned char' for numeric values.",
                                    child_text
                                ),
                                severity: self.severity(),
                                line: child.start_position().row + 1,
                                column: child.start_position().column + 1,
                                file_path: String::new(),
                                suggestion: Some(format!(
                                    "Change declaration of '{}' from 'char' to 'signed char' or 'unsigned char'",
                                    child_text
                                )),
                                requires_manual_review: None,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Check if a node represents a numeric literal
    fn is_numeric_literal(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "number_literal" {
            return true;
        }

        // Also check for negative numeric literals (unary -)
        if node.kind() == "unary_expression" {
            if let Some(operator) = node.child_by_field_name("operator") {
                let op_text = get_node_text(&operator, source);
                if op_text == "-" || op_text == "+" {
                    if let Some(argument) = node.child_by_field_name("argument") {
                        return self.is_numeric_literal(&argument, source);
                    }
                }
            }
        }

        false
    }

    /// Extract variable name from declaration
    fn extract_var_name(&self, decl: &Node, source: &str) -> Option<String> {
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    return self.find_identifier(&child, source);
                } else if child.kind() == "identifier" {
                    return Some(get_node_text(&child, source).to_string());
                }
            }
        }
        None
    }

    /// Extract parameter name from parameter declaration
    fn extract_param_name(&self, param: &Node, source: &str) -> Option<String> {
        for i in 0..param.child_count() {
            if let Some(child) = param.child(i) {
                if child.kind() == "identifier" {
                    return Some(get_node_text(&child, source).to_string());
                }
            }
        }
        None
    }

    /// Find identifier in node tree
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
}
