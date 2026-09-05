// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! MSC20-C: Do not use a switch statement to transfer control into a
//! complex block
//!
//! A `case`/`default` label is only well-structured when it sits directly in
//! the switch's own body. If a label appears nested inside a `for`/`while`/
//! `do`/`if` block that spans more than one case (e.g. Duff's device, or a
//! case label placed inside a `for` loop body started by an earlier case),
//! the switch jumps directly into the middle of that block, skipping its
//! initialization -- extremely easy to misread and modify incorrectly. This
//! rule flags any case/default label whose nearest enclosing switch is
//! reached by passing through a `for`/`while`/`do`/`if` block along the way.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/MSC20-C.+Do+not+use+a+switch+statement+to+transfer+control+into+a+complex+block

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use lang_parsing_substrate::query;
use tree_sitter::Node;

const COMPLEX_BLOCK_KINDS: &[&str] = &[
    "for_statement",
    "while_statement",
    "do_statement",
    "if_statement",
];

#[derive(Debug)]
pub struct Msc20C;

impl Msc20C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Msc20C
    }

    fn traverse(&self, root: &Node, _source: &str, violations: &mut Vec<RuleViolation>) {
        for label in query::find_descendants_of_kind(*root, "case_statement") {
            let mut current = label.parent();
            let mut passed_through_complex_block = false;
            while let Some(node) = current {
                if node.kind() == "switch_statement" {
                    break;
                }
                if COMPLEX_BLOCK_KINDS.contains(&node.kind()) {
                    passed_through_complex_block = true;
                }
                current = node.parent();
            }

            if passed_through_complex_block {
                let pos = label.start_position();
                violations.push(RuleViolation {
                    rule_id: "MSC20-C".to_string(),
                    severity: Severity::Medium,
                    line: pos.row + 1,
                    column: pos.column + 1,
                    message: "switch jumps into the middle of a for/while/do/if block via this case label, skipping its initialization".to_string(),
                    file_path: String::new(),
                    suggestion: Some(
                        "Restructure so every case label sits directly in the switch's own body, not nested inside a loop or if block that spans multiple cases"
                            .to_string(),
                    ),
                    requires_manual_review: Some(false),
                });
            }
        }
    }
}

impl CertRule for Msc20C {
    fn rule_id(&self) -> &'static str {
        "MSC20-C"
    }

    fn description(&self) -> &'static str {
        "Do not use a switch statement to transfer control into a complex block"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "MSC20-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }
}
