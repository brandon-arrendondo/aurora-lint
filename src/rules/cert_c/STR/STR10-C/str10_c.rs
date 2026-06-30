use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use tree_sitter::Node;

pub struct Str10C;

impl CertRule for Str10C {
    fn rule_id(&self) -> &'static str {
        "STR10-C"
    }

    fn description(&self) -> &'static str {
        "Do not concatenate different type of string literals"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "STR10-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check for string concatenation (adjacent string literals)
        if node.kind() == "concatenated_string" {
            self.check_string_literal_types(node, source, &mut violations);
        }

        // Also check init_declarator which might have concatenated strings
        if node.kind() == "init_declarator" {
            if let Some(value) = node.child_by_field_name("value") {
                if value.kind() == "concatenated_string" {
                    self.check_string_literal_types(&value, source, &mut violations);
                }
            }
        }

        // Recursively check child nodes
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                violations.extend(self.check(&child, source));
            }
        }

        violations
    }
}

impl Str10C {
    /// Check if concatenated strings mix wide and narrow literals
    fn check_string_literal_types(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let mut has_wide = false;
        let mut has_narrow = false;

        // Examine all child string literals
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "string_literal" {
                    let text = ast_utils::get_node_text(&child, source);

                    // Wide string literals start with L"
                    if text.starts_with("L\"") || text.starts_with("L'") {
                        has_wide = true;
                    } else if text.starts_with('"') || text.starts_with('\'') {
                        has_narrow = true;
                    }
                }
            }
        }

        // If we have both types, it's a violation
        if has_wide && has_narrow {
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                message: "Mixing wide and narrow string literals in concatenation".to_string(),
                file_path: String::new(),
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                suggestion: Some(
                    "Use consistent string literal types (all narrow or all wide)".to_string(),
                ),
                ..Default::default()
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_c_code(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&crate::parser::c_language())
            .expect("Error loading C grammar");
        parser.parse(source, None).expect("Error parsing C code")
    }

    #[test]
    fn test_mixed_string_literals() {
        let code = r#"
wchar_t *msg = L"This is wide "
                "and this is narrow";
"#;
        let tree = parse_c_code(code);
        let rule = Str10C;
        let violations = rule.check(&tree.root_node(), code);
        assert!(
            !violations.is_empty(),
            "Should detect mixed wide and narrow string literals"
        );
    }

    #[test]
    fn test_consistent_narrow_literals() {
        let code = r#"
char *msg = "This is narrow "
            "and this too";
"#;
        let tree = parse_c_code(code);
        let rule = Str10C;
        let violations = rule.check(&tree.root_node(), code);
        assert!(
            violations.is_empty(),
            "Should not flag consistent narrow literals"
        );
    }

    #[test]
    fn test_consistent_wide_literals() {
        let code = r#"
wchar_t *msg = L"This is wide "
               L"and this too";
"#;
        let tree = parse_c_code(code);
        let rule = Str10C;
        let violations = rule.check(&tree.root_node(), code);
        assert!(
            violations.is_empty(),
            "Should not flag consistent wide literals"
        );
    }
}
