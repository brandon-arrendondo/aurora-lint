use crate::manifest::{RuleCategory, Severity};
use crate::prelude::RuleViolation;
use crate::rules::cert_c::CertRule;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pos01C;

impl CertRule for Pos01C {
    fn rule_id(&self) -> &'static str {
        "POS01-C"
    }

    fn cert_id(&self) -> &'static str {
        "POS01"
    }

    fn description(&self) -> &'static str {
        "Check for the existence of links when dealing with files"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check both inside functions and at top-level (translation_unit)
        if node.kind() == "translation_unit" {
            // For top-level code, check if there's any lstat() in the entire file
            let has_lstat = self.subtree_has_lstat(node, source);
            self.check_open_calls_recursive(node, source, has_lstat, &mut violations);
        } else {
            // Check functions individually
            self.check_functions(node, source, &mut violations);
        }

        violations
    }
}

impl Pos01C {
    fn check_functions(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            // Check this function for open() without proper protection
            let has_lstat = self.subtree_has_lstat(&func, source);
            self.check_open_calls_recursive(&func, source, has_lstat, violations);
        }
    }

    fn subtree_has_lstat(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let mut cursor = n.walk();
            let found = n.children(&mut cursor).any(|child| {
                child.kind() == "identifier" && get_node_text(&child, source) == "lstat"
            });
            found
        })
        .is_some()
    }

    fn check_open_calls_recursive(
        &self,
        node: &Node,
        source: &str,
        has_lstat: bool,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            // Check if this is an open() call
            let mut cursor = n.walk();
            let mut is_open = false;
            let mut has_nofollow = false;

            for child in n.children(&mut cursor) {
                if child.kind() == "identifier" {
                    let func_name = get_node_text(&child, source);
                    if func_name == "open" {
                        is_open = true;
                    }
                }

                // Check arguments for O_NOFOLLOW
                if child.kind() == "argument_list" {
                    has_nofollow = self.has_nofollow_flag(&child, source);
                }
            }

            if is_open && !has_nofollow && !has_lstat {
                // Flag open() without O_NOFOLLOW and without lstat() validation
                let start = n.start_position();
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    file_path: String::new(),
                    message: "open() called without O_NOFOLLOW flag and without lstat() validation. This may be vulnerable to symlink attacks.".to_string(),
                    line: start.row + 1,
                    column: start.column + 1,
                    severity: self.severity(),
                    suggestion: Some("Use O_NOFOLLOW flag in open() call, or validate with lstat() before opening".to_string()),
                    requires_manual_review: Some(false),
                });
            }
        }
    }

    fn has_nofollow_flag(&self, node: &Node, source: &str) -> bool {
        // Check if any argument contains O_NOFOLLOW
        let text = get_node_text(node, source);
        text.contains("O_NOFOLLOW")
    }
}
