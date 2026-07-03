//! POS55-C: Ensure correct socket operation ordering
//!
//! Socket lifecycle operations must follow the correct order:
//! socket() → bind() → listen() → accept()
//!
//! Calling accept() before bind()/listen(), or listen() before bind(),
//! results in undefined behavior or silent failure.

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pos55C;

impl CertRule for Pos55C {
    fn rule_id(&self) -> &'static str {
        "POS55-C"
    }

    fn description(&self) -> &'static str {
        "Ensure correct socket operation ordering (bind before listen before accept)"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "POS55-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Pos55C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(body) = func.child_by_field_name("body") {
                self.check_socket_ordering(&body, source, violations);
            }
        }
    }

    fn check_socket_ordering(
        &self,
        body: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Collect positions of socket API calls in source order
        let mut bind_pos: Option<(usize, usize, usize)> = None; // (byte_offset, line, col)
        let mut listen_pos: Option<(usize, usize, usize)> = None;
        let mut accept_pos: Option<(usize, usize, usize)> = None;

        self.scan_socket_calls(
            body,
            source,
            &mut bind_pos,
            &mut listen_pos,
            &mut accept_pos,
        );

        // Check ordering violations
        // Correct order: bind → listen → accept
        if let Some((accept_byte, accept_line, accept_col)) = accept_pos {
            if let Some((bind_byte, _, _)) = bind_pos {
                if accept_byte < bind_byte {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: "accept() called before bind() — socket not yet bound to address"
                            .to_string(),
                        file_path: String::new(),
                        line: accept_line,
                        column: accept_col,
                        suggestion: Some(
                            "Call bind() before accept(). Correct order: bind() → listen() → accept()"
                                .to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
            if let Some((listen_byte, _, _)) = listen_pos {
                if accept_byte < listen_byte {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message:
                            "accept() called before listen() — socket not yet in listening state"
                                .to_string(),
                        file_path: String::new(),
                        line: accept_line,
                        column: accept_col,
                        suggestion: Some(
                            "Call listen() before accept(). Correct order: bind() → listen() → accept()"
                                .to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }

        if let Some((listen_byte, listen_line, listen_col)) = listen_pos {
            if let Some((bind_byte, _, _)) = bind_pos {
                if listen_byte < bind_byte {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: "listen() called before bind() — socket not yet bound to address"
                            .to_string(),
                        file_path: String::new(),
                        line: listen_line,
                        column: listen_col,
                        suggestion: Some(
                            "Call bind() before listen(). Correct order: bind() → listen() → accept()"
                                .to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    fn scan_socket_calls(
        &self,
        node: &Node,
        source: &str,
        bind_pos: &mut Option<(usize, usize, usize)>,
        listen_pos: &mut Option<(usize, usize, usize)>,
        accept_pos: &mut Option<(usize, usize, usize)>,
    ) {
        for node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func) = node.child_by_field_name("function") {
                let name = get_node_text(&func, source).trim().to_string();
                let pos = (
                    node.start_byte(),
                    node.start_position().row + 1,
                    node.start_position().column + 1,
                );
                match name.as_str() {
                    "bind" if bind_pos.is_none() => {
                        *bind_pos = Some(pos);
                    }
                    "listen" if listen_pos.is_none() => {
                        *listen_pos = Some(pos);
                    }
                    "accept" if accept_pos.is_none() => {
                        *accept_pos = Some(pos);
                    }
                    _ => {}
                }
            }
        }
    }
}
