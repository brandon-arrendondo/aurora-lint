// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{get_node_text, resolve_identifier_declarator};
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Fio44C;

impl CertRule for Fio44C {
    fn rule_id(&self) -> &'static str {
        "FIO44-C"
    }

    fn description(&self) -> &'static str {
        "Only use values for fsetpos() that are returned from fgetpos()"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        self.rule_id()
    }

    fn check(&self, root: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Track fpos_t variables and whether they were initialized by fgetpos,
        // keyed by the declaration each name resolves to (ADR-0006): an
        // `fpos_t pos;` in one function says nothing about a `pos` in another.
        let mut fpos_vars = std::collections::HashMap::new();
        self.track_fpos_vars(root, source, &mut fpos_vars);

        // Check fsetpos calls
        self.check_fsetpos_calls(root, source, &fpos_vars, &mut violations);

        violations
    }
}

/// A declared variable: the declaration's start byte and the bound name.
type DeclKey = (usize, String);

impl Fio44C {
    fn track_fpos_vars(
        &self,
        node: &Node,
        source: &str,
        fpos_vars: &mut std::collections::HashMap<DeclKey, bool>,
    ) {
        for n in query::find_descendants(*node, |_| true) {
            // Look for fpos_t declarations
            if n.kind() == "declaration" {
                let decl_text = get_node_text(&n, source);
                if decl_text.contains("fpos_t") {
                    // Extract variable name (simple heuristic)
                    if let Some(declarator) = n.child_by_field_name("declarator") {
                        if let Some(ident) = self.get_identifier(&declarator, source) {
                            fpos_vars.insert((n.start_byte(), ident.to_string()), false);
                        }
                    }
                }
            }
        }

        // Credit the declaration each fgetpos() output argument resolves to.
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(key) = self.position_argument_decl(&n, "fgetpos", source) {
                if let Some(initialized) = fpos_vars.get_mut(&key) {
                    *initialized = true;
                }
            }
        }
    }

    /// For a call to `callee`, the declaration its second argument (`&pos`
    /// or `pos`) resolves to. None for another call, or an argument that is
    /// not a plain variable or does not resolve.
    fn position_argument_decl(&self, call: &Node, callee: &str, source: &str) -> Option<DeclKey> {
        let func_node = call.child_by_field_name("function")?;
        if get_node_text(&func_node, source) != callee {
            return None;
        }
        let mut arg = call.child_by_field_name("arguments")?.named_child(1)?;
        loop {
            match arg.kind() {
                "parenthesized_expression" => arg = arg.named_child(0)?,
                "pointer_expression"
                    if arg
                        .child_by_field_name("operator")
                        .is_some_and(|op| get_node_text(&op, source) == "&") =>
                {
                    arg = arg.child_by_field_name("argument")?
                }
                _ => break,
            }
        }
        if arg.kind() != "identifier" {
            return None;
        }
        let name = get_node_text(&arg, source);
        let (decl, _) = resolve_identifier_declarator(&arg, name, source)?;
        Some((decl.start_byte(), name.to_string()))
    }

    fn check_fsetpos_calls(
        &self,
        node: &Node,
        source: &str,
        fpos_vars: &std::collections::HashMap<DeclKey, bool>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            let Some(key) = self.position_argument_decl(&n, "fsetpos", source) else {
                continue;
            };
            // Check if this fpos_t was initialized by fgetpos
            if fpos_vars.get(&key) == Some(&false) {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: "fsetpos() called with value not obtained from fgetpos()".to_string(),
                    file_path: String::new(),
                    line: n.start_position().row + 1,
                    column: n.start_position().column + 1,
                    suggestion: None,
                    requires_manual_review: None,
                });
            }
        }
    }

    fn get_identifier<'a>(&self, node: &Node<'a>, source: &'a str) -> Option<&'a str> {
        query::find_first_descendant(*node, |n| n.kind() == "identifier")
            .map(|n| get_node_text(&n, source))
    }
}
