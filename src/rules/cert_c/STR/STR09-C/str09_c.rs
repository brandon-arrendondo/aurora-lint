//! STR09-C: Don't assume numeric values for expressions with type plain character
//!
//! This rule detects ordering comparisons (<, >, <=, >=) on plain char values
//! with non-digit character literals, as character ordering is not guaranteed
//! to be consistent across character sets (except for digits '0'-'9').
//!
//! VIOLATIONS:
//! - ch >= 'a' (ordering comparison on non-digit char)
//! - ch < 'Z' (ordering comparison on non-digit char)
//!
//! COMPLIANT:
//! - ch == 'a' (equality comparison is always safe)
//! - ch >= '0' && ch <= '9' (digit comparisons are portable)

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Str09C;

// Ordering comparison operators
const ORDERING_OPS: &[&str] = &["<", ">", "<=", ">="];

impl CertRule for Str09C {
    fn rule_id(&self) -> &'static str {
        "STR09-C"
    }

    fn description(&self) -> &'static str {
        "Don't assume numeric values for expressions with type plain character"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "STR09-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let mut char_vars: HashMap<String, bool> = HashMap::new();

        // First pass: collect char variables
        self.collect_char_vars(node, source, &mut char_vars);

        // Second pass: check for violations
        self.check_node(node, source, &mut violations, &char_vars);
        violations
    }
}

impl Str09C {
    fn collect_char_vars(&self, node: &Node, source: &str, char_vars: &mut HashMap<String, bool>) {
        for node in query::find_descendants_of_kind(*node, "declaration") {
            // Check if this is a char declaration
            let mut is_char = false;
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "primitive_type" {
                        let type_text = get_node_text(&child, source);
                        if type_text == "char" {
                            is_char = true;
                        }
                    }
                }
            }
            if is_char {
                // Find the variable name(s)
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if let Some(name) = self.extract_var_name(&child, source) {
                            char_vars.insert(name, true);
                        }
                    }
                }
            }
        }
    }

    fn extract_var_name(&self, node: &Node, source: &str) -> Option<String> {
        let kind = node.kind();
        if kind == "identifier" {
            return Some(get_node_text(node, source).to_string());
        }
        if kind == "init_declarator" || kind == "pointer_declarator" {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if let Some(name) = self.extract_var_name(&child, source) {
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
        char_vars: &HashMap<String, bool>,
    ) {
        // Check binary expressions for ordering comparisons
        for n in query::find_descendants_of_kind(*node, "binary_expression") {
            self.check_binary_expr(&n, source, violations, char_vars);
        }
    }

    fn check_binary_expr(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        char_vars: &HashMap<String, bool>,
    ) {
        // Get operator
        let mut operator = None;
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let text = get_node_text(&child, source);
                if ORDERING_OPS.contains(&text) {
                    operator = Some(text.to_string());
                    break;
                }
            }
        }

        let op = match operator {
            Some(o) => o,
            None => return, // Not an ordering comparison
        };

        // Get left and right operands
        let left = match node.child_by_field_name("left") {
            Some(l) => l,
            None => return,
        };
        let right = match node.child_by_field_name("right") {
            Some(r) => r,
            None => return,
        };

        // Check if either side involves a char variable and a non-digit char literal
        let left_is_char_var = self.is_char_expression(&left, source, char_vars);
        let right_is_char_var = self.is_char_expression(&right, source, char_vars);

        let left_char_lit = self.get_char_literal(&left, source);
        let right_char_lit = self.get_char_literal(&right, source);

        // Check for violation: char var compared with non-digit char literal
        if left_is_char_var {
            if let Some(c) = &right_char_lit {
                if !self.is_digit_char(c) {
                    self.report_violation(node, source, violations, &op, c);
                    return;
                }
            }
        }

        if right_is_char_var {
            if let Some(c) = &left_char_lit {
                if !self.is_digit_char(c) {
                    self.report_violation(node, source, violations, &op, c);
                    return;
                }
            }
        }

        // Also check if both are char literals (non-digit)
        if let (Some(l), Some(r)) = (&left_char_lit, &right_char_lit) {
            if !self.is_digit_char(l) || !self.is_digit_char(r) {
                self.report_violation(node, source, violations, &op, l);
            }
        }
    }

    fn is_char_expression(
        &self,
        node: &Node,
        source: &str,
        char_vars: &HashMap<String, bool>,
    ) -> bool {
        if node.kind() == "identifier" {
            let name = get_node_text(node, source);
            return char_vars.contains_key(name);
        }
        if node.kind() == "parenthesized_expression" {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if self.is_char_expression(&child, source, char_vars) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn get_char_literal(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "char_literal" {
            return Some(get_node_text(node, source).to_string());
        }
        if node.kind() == "parenthesized_expression" {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if let Some(c) = self.get_char_literal(&child, source) {
                        return Some(c);
                    }
                }
            }
        }
        None
    }

    fn is_digit_char(&self, char_lit: &str) -> bool {
        // char_lit is like '0', '1', ..., '9'
        if char_lit.len() >= 3 && char_lit.starts_with('\'') && char_lit.ends_with('\'') {
            let c = &char_lit[1..char_lit.len() - 1];
            if c.len() == 1 {
                let ch = c.chars().next().unwrap();
                return ch.is_ascii_digit();
            }
        }
        false
    }

    fn report_violation(
        &self,
        node: &Node,
        _source: &str,
        violations: &mut Vec<RuleViolation>,
        op: &str,
        char_lit: &str,
    ) {
        let pos = node.start_position();
        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::Low,
            message: format!(
                "Ordering comparison '{}' on character {} is non-portable; only digit characters have guaranteed ordering",
                op, char_lit
            ),
            file_path: String::new(),
            line: pos.row + 1,
            column: pos.column + 1,
            suggestion: Some(
                "Use == and != for non-digit characters, or use <ctype.h> functions".to_string()
            ),
            ..Default::default()
        });
    }
}
