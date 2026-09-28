// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::analyze::macro_expand::{operand_params_in_scope, OperandParams};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::pp_tokens::{
    define_directives, in_sorted_ranges, is_spelled_operand, LineIndex, PpKind,
};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use tree_sitter::{Node, Point};

pub struct Dcl18C {
    /// Which parameters each function-like macro stringizes or pastes
    /// (`ProjectContext::macro_operand_params`): a number passed to one
    /// inside a replacement list is spelled, never an integer constant.
    operand_params: RefCell<Arc<HashMap<String, OperandParams>>>,
}

impl Dcl18C {
    pub fn new() -> Self {
        Self {
            operand_params: RefCell::default(),
        }
    }
}

impl CertRule for Dcl18C {
    fn rule_id(&self) -> &'static str {
        "DCL18-C"
    }

    fn description(&self) -> &'static str {
        "Do not begin integer constants with 0 when specifying a decimal value"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "DCL18-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.operand_params.borrow_mut() = context.macro_operand_params.clone();
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Recursively check for octal literals
        violations.extend(self.check_node(*node, source));

        violations
    }
}

impl Dcl18C {
    /// Recursively check nodes for integer literals that appear to be unintended octals
    /// A `#define`'s replacement list is one opaque token to tree-sitter, so
    /// its literals come from the pp-token lexer, and the AST nodes inside a
    /// directive (which exist only where tree-sitter misparsed it) are
    /// skipped.
    fn check_node(&self, node: Node, source: &str) -> Vec<RuleViolation> {
        let defines = define_directives(&node, source);
        let ranges: Vec<_> = defines.iter().map(|(range, _)| range.clone()).collect();
        let mut violations: Vec<RuleViolation> =
            query::find_descendants_of_kind(node, "number_literal")
                .into_iter()
                .filter(|n| !in_sorted_ranges(&ranges, n.start_byte()))
                .filter_map(|n| self.check_literal(get_node_text(&n, source), n.start_position()))
                .collect();
        let lines = (!defines.is_empty()).then(|| LineIndex::new(source));
        let params = operand_params_in_scope(&self.operand_params.borrow(), source);
        let is_operand_argument =
            |name: &str, index: usize| params.get(name).is_some_and(|p| p.covers_argument(index));
        for (_, define) in &defines {
            let tokens = define.tokens();
            for (k, token) in tokens.iter().enumerate() {
                if token.kind == PpKind::Number
                    && !is_spelled_operand(&tokens, k, is_operand_argument)
                {
                    let at = lines.as_ref().map_or_else(Default::default, |l| {
                        l.point(define.body_start + token.start)
                    });
                    violations.extend(self.check_literal(&token.text, at));
                }
            }
        }
        violations.sort_by_key(|v| (v.line, v.column));
        violations
    }

    /// Check if the integer literal `literal_text`, at `at`, is an
    /// unintended octal constant.
    fn check_literal(&self, literal_text: &str, at: Point) -> Option<RuleViolation> {
        // Check if this is an octal literal (starts with 0 but is not a special case)
        if self.is_unintended_octal(&literal_text) {
            let decimal_value = self.parse_octal_as_decimal(&literal_text);

            let value = match self.octal_to_decimal(&literal_text) {
                Some(v) => format!("This evaluates to {} in decimal.", v),
                None => "It is not a valid octal constant.".to_string(),
            };
            let message = format!(
                "Integer constant '{}' begins with 0, making it octal (base-8). {} \
                If you intended decimal {}, remove the leading 0. \
                If you intended octal, consider using explicit base notation for clarity",
                literal_text, value, decimal_value
            );

            let suggestion = format!(
                "Remove leading 0: use '{}' for decimal, or keep '{}' if octal was intended",
                decimal_value, literal_text
            );

            return Some(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                message,
                file_path: String::new(),
                line: at.row + 1,
                column: at.column + 1,
                suggestion: Some(suggestion),
                ..Default::default()
            });
        }

        None
    }

    /// Check if a literal string represents an unintended octal constant
    fn is_unintended_octal(&self, literal: &str) -> bool {
        // Must start with '0'
        if !literal.starts_with('0') {
            return false;
        }

        // Filter out legitimate cases:
        // - Just "0" (zero)
        if literal == "0" {
            return false;
        }

        // - Hexadecimal (0x or 0X)
        if literal.starts_with("0x") || literal.starts_with("0X") {
            return false;
        }

        // - Binary (0b or 0B) - C23 extension
        if literal.starts_with("0b") || literal.starts_with("0B") {
            return false;
        }

        // - Floating point (0.something or 0e/0E for scientific notation)
        if literal.contains('.') || literal.contains('e') || literal.contains('E') {
            return false;
        }

        // - Zero with type suffix (0U, 0u, 0L, 0l, 0UL, 0ul, 0LL, 0ULL, etc.)
        //   "0U" is unsigned zero, "0L" is long zero — never octal confusion.
        let stripped = literal.trim_end_matches(['u', 'U', 'l', 'L']);
        if stripped == "0" {
            return false;
        }

        // Check if it has more digits after the leading 0
        // This catches cases like "0042", "0123", etc.
        if literal.len() > 1 {
            // Make sure the characters after '0' are digits (octal digits 0-7)
            // This is an octal literal
            return true;
        }

        false
    }

    /// Parse octal literal text as if it were decimal (what programmer likely intended)
    fn parse_octal_as_decimal(&self, literal: &str) -> String {
        // Remove leading zeros and return the numeric part
        literal.trim_start_matches('0').to_string()
    }

    /// The octal literal's decimal value, or `None` when its digits are not
    /// valid octal (`09`) or it overflows. The integer suffix is dropped
    /// first: `017L` is 15, and parsing the `L` along with the digits failed
    /// and was reported as 0.
    fn octal_to_decimal(&self, literal: &str) -> Option<u64> {
        let digits = literal
            .trim_end_matches(['u', 'U', 'l', 'L'])
            .trim_start_matches('0');
        if digits.is_empty() {
            return Some(0);
        }
        u64::from_str_radix(digits, 8).ok()
    }
}
