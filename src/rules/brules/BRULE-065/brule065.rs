use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use tree_sitter::Node;

/// Maximum allowed pointer indirection depth.
const MAX_POINTER_DEPTH: usize = 2;

pub struct Brule065;

impl CertRule for Brule065 {
    fn rule_id(&self) -> &'static str {
        "BRULE-065"
    }
    fn description(&self) -> &'static str {
        "Do not use excessive pointer indirection"
    }
    fn severity(&self) -> Severity {
        Severity::Low
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }
    fn cert_id(&self) -> &'static str {
        "BRULE-065"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.walk(node, source, violations);
    }
}

impl Brule065 {
    fn walk(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() == "declaration" {
            self.check_declaration(node, source, violations);
        }
        // Also check parameter declarations
        if node.kind() == "parameter_declaration" {
            self.check_declaration(node, source, violations);
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.walk(&child, source, violations);
            }
        }
    }

    fn check_declaration(&self, decl: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Find the declarator subtree and count pointer depth
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                match child.kind() {
                    "pointer_declarator" | "init_declarator" => {
                        let depth = self.count_pointer_depth(&child);
                        if depth > MAX_POINTER_DEPTH {
                            let name = self
                                .extract_identifier(&child, source)
                                .unwrap_or_else(|| get_node_text(&child, source));
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: self.severity(),
                                message: format!(
                                    "Excessive pointer indirection depth ({}) in declaration of '{}' (max {})",
                                    depth, name, MAX_POINTER_DEPTH
                                ),
                                file_path: String::new(),
                                line: child.start_position().row + 1,
                                column: child.start_position().column + 1,
                                suggestion: Some(
                                    "Reduce pointer indirection by using intermediate typedefs or restructuring".to_string(),
                                ),
                                ..Default::default()
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Count the pointer indirection depth by walking nested pointer_declarator nodes.
    fn count_pointer_depth(&self, node: &Node) -> usize {
        let mut depth = 0;
        let mut current = *node;

        loop {
            match current.kind() {
                "pointer_declarator" => {
                    depth += 1;
                    // Look for nested pointer_declarator or other declarator
                    let mut found_child = false;
                    for i in 0..current.child_count() {
                        if let Some(child) = current.child(i) {
                            match child.kind() {
                                "pointer_declarator"
                                | "array_declarator"
                                | "function_declarator" => {
                                    current = child;
                                    found_child = true;
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                    if !found_child {
                        break;
                    }
                }
                "init_declarator" => {
                    // Skip the init_declarator wrapper, look at its declarator child
                    let mut found_child = false;
                    for i in 0..current.child_count() {
                        if let Some(child) = current.child(i) {
                            match child.kind() {
                                "pointer_declarator"
                                | "array_declarator"
                                | "function_declarator"
                                | "identifier" => {
                                    current = child;
                                    found_child = true;
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                    if !found_child {
                        break;
                    }
                }
                _ => break,
            }
        }

        depth
    }

    /// Extract the identifier name from a declarator subtree.
    fn extract_identifier<'a>(&self, node: &Node, source: &'a str) -> Option<&'a str> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source));
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(name) = self.extract_identifier(&child, source) {
                    return Some(name);
                }
            }
        }
        None
    }
}
