// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

// DCL16-C: Use "L," not "l," to indicate a long value
//
// This rule detects integer literals that use lowercase 'l' suffix instead
// of uppercase 'L', which can be confused with the digit '1'.
//
// Detection strategy:
// 1. Find all number literals in the code
// 2. Check if they end with lowercase 'l' or 'll'
// 3. Flag violations and suggest using uppercase 'L' or 'LL'

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::analyze::macro_expand::{operand_params_in_scope, OperandParams};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::node_children::NodeChildren;
use crate::utility::cert_c::pp_tokens::{
    define_directives, in_sorted_ranges, is_spelled_operand, LineIndex, PpKind,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use tree_sitter::{Node, Point};

pub struct Dcl16C {
    /// Which parameters each function-like macro stringizes or pastes
    /// (`ProjectContext::macro_operand_params`): a number passed to one
    /// inside a replacement list is spelled, never an integer constant.
    operand_params: RefCell<Arc<HashMap<String, OperandParams>>>,
}

impl Dcl16C {
    pub fn new() -> Self {
        Self {
            operand_params: RefCell::default(),
        }
    }

    /// Check a node and all its descendants for violations, skipping the
    /// `#define` directives in `defines`, whose literals are read from their
    /// tokens instead.
    fn check_node<'a>(
        &self,
        node: &Node<'a>,
        source: &'a str,
        defines: &[std::ops::Range<usize>],
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() == "number_literal" {
            if !in_sorted_ranges(defines, node.start_byte()) {
                self.check_literal(
                    get_node_text(node, source),
                    node.start_position(),
                    violations,
                );
            }
        }

        // Recurse into children
        for child in node.child_nodes() {
            self.check_node(&child, source, defines, violations);
        }
    }

    /// Check one integer literal, spelled `text` at `at`.
    fn check_literal(&self, text: &str, at: Point, violations: &mut Vec<RuleViolation>) {
        // Check for lowercase 'l' or 'll' suffix
        if self.has_lowercase_long_suffix(text) {
            let suggested = self.fix_lowercase_suffix(text);

            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                line: at.row + 1,
                column: at.column + 1,
                message: format!(
                    "Integer literal '{}' uses lowercase 'l' suffix which can be confused with digit '1'",
                    text
                ),
                severity: self.severity(),
                file_path: String::new(),
                suggestion: Some(format!("Use uppercase 'L': {}", suggested)),
                requires_manual_review: None,
            });
        }
    }

    /// Check if number has lowercase 'l' or 'll' suffix
    fn has_lowercase_long_suffix(&self, text: &str) -> bool {
        // Remove any unsigned suffix first
        let text = text.trim_end_matches('u').trim_end_matches('U');

        // Check for lowercase 'l' or 'll' at the end
        text.ends_with("ll") || (text.ends_with('l') && !text.ends_with('L'))
    }

    /// Fix lowercase suffix to uppercase
    fn fix_lowercase_suffix(&self, text: &str) -> String {
        let mut result = text.to_string();

        // Handle unsigned suffix
        let has_u_suffix = result.ends_with('u') || result.ends_with('U');
        let u_suffix = if has_u_suffix {
            let suffix = result.chars().last().unwrap();
            result.pop();
            Some(suffix)
        } else {
            None
        };

        // Replace lowercase 'l' with 'L'
        if result.ends_with("ll") {
            result = result[..result.len() - 2].to_string() + "LL";
        } else if result.ends_with('l') {
            result = result[..result.len() - 1].to_string() + "L";
        }

        // Restore unsigned suffix
        if let Some(u) = u_suffix {
            result.push(u);
        }

        result
    }
}

impl CertRule for Dcl16C {
    fn rule_id(&self) -> &'static str {
        "DCL16-C"
    }

    fn description(&self) -> &'static str {
        "Use \"L,\" not \"l,\" to indicate a long value"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "DCL16-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.operand_params.borrow_mut() = context.macro_operand_params.clone();
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // A `#define`'s replacement list is one opaque token to tree-sitter,
        // so its literals come from the pp-token lexer.
        let defines = define_directives(node, source);
        let ranges: Vec<_> = defines.iter().map(|(range, _)| range.clone()).collect();
        self.check_node(node, source, &ranges, violations);
        if defines.is_empty() {
            return;
        }
        let lines = LineIndex::new(source);
        let params = operand_params_in_scope(&self.operand_params.borrow(), source);
        let is_operand_argument =
            |name: &str, index: usize| params.get(name).is_some_and(|p| p.covers_argument(index));
        for (_, define) in &defines {
            let tokens = define.tokens();
            for (k, token) in tokens.iter().enumerate() {
                if token.kind == PpKind::Number
                    && !is_spelled_operand(&tokens, k, is_operand_argument)
                {
                    let at = lines.point(define.body_start + token.start);
                    self.check_literal(&token.text, at, violations);
                }
            }
        }
        violations.sort_by_key(|v| (v.line, v.column));
    }
}
