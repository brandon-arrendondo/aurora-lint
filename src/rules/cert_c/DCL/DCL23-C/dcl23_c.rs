// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Ryan Urchick

use std::collections::HashMap;
use tree_sitter::Node;

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;

pub struct Dcl23C;

impl CertRule for Dcl23C {
    fn rule_id(&self) -> &'static str {
        "DCL23-C"
    }
    fn description(&self) -> &'static str {
        "Guarantee that mutually visible identifiers are unique"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }
    fn cert_id(&self) -> &'static str {
        "DCL23-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let mut identifiers: HashMap<String, Vec<(String, usize, usize)>> = HashMap::new();

        self.collect_identifiers(node, source, &mut identifiers);

        for (_base, variants) in identifiers.iter() {
            if variants.len() > 1 && self.variants_too_similar(&variants) {
                for (name, line, col) in variants {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: *line,
                        column: *col,
                        file_path: String::new(),
                        message: format!(
                            "Identifier '{}' differs from similar identifiers only in trailing characters",
                            name
                        ),
                        suggestion: Some(
                            "Use more distinctive names that differ at the beginning".to_string()
                        ),
                        requires_manual_review: None,
                    });
                }
            }
        }
        violations
    }
}

impl Dcl23C {
    fn collect_identifiers(
        &self,
        node: &Node,
        source: &str,
        ids: &mut HashMap<String, Vec<(String, usize, usize)>>,
    ) {
        if node.kind() == "declaration" {
            let text = get_node_text(node, source);
            if text.starts_with("extern") {
                if let Some((name, line, col)) = self.find_identifier_info(node, source) {
                    let base = if name.len() > 1 {
                        name[..name.len() - 1].to_string()
                    } else {
                        name.clone()
                    };
                    ids.entry(base).or_default().push((name, line, col));
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.collect_identifiers(&child, source, ids);
        }
    }

    fn find_identifier_info(&self, node: &Node, source: &str) -> Option<(String, usize, usize)> {
        if node.kind() == "identifier" {
            let name = get_node_text(node, source).to_string();
            let pos = node.start_position();
            return Some((name, pos.row + 1, pos.column + 1));
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(info) = self.find_identifier_info(&child, source) {
                return Some(info);
            }
        }
        None
    }

    fn variants_too_similar(&self, variants: &[(String, usize, usize)]) -> bool {
        if variants.len() < 2 {
            return false;
        }
        let first = &variants[0].0;
        let min_len = variants.iter().map(|(n, _, _)| n.len()).min().unwrap_or(0);
        if min_len < 2 {
            return false;
        }

        let mut prefix_len = 0;
        for i in 0..min_len {
            let ch = first.chars().nth(i).unwrap();
            if variants
                .iter()
                .all(|(n, _, _)| n.chars().nth(i) == Some(ch))
            {
                prefix_len = i + 1;
            } else {
                break;
            }
        }

        prefix_len as f64 / min_len as f64 >= 0.7
    }
}
