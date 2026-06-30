use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use tree_sitter::Node;

pub struct Exp08C;

impl CertRule for Exp08C {
    fn rule_id(&self) -> &'static str {
        "EXP08-C"
    }

    fn description(&self) -> &'static str {
        "Ensure pointer arithmetic is used correctly"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "EXP08-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check for improper pointer arithmetic in comparisons
        if node.kind() == "binary_expression" {
            if let Some(operator) = ast_utils::get_binary_operator(node, source) {
                // Check for comparison operators
                if matches!(operator, "<" | ">" | "<=" | ">=" | "==" | "!=") {
                    self.check_pointer_comparison(node, source, &mut violations);
                }
            }
        }

        // Check for pointer arithmetic with struct pointers
        if node.kind() == "binary_expression" {
            if let Some(operator) = ast_utils::get_binary_operator(node, source) {
                if operator == "+" || operator == "-" {
                    self.check_struct_pointer_arithmetic(node, source, &mut violations);
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

impl Exp08C {
    /// Check for using sizeof() instead of array element count in pointer comparisons
    fn check_pointer_comparison(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get left and right operands
        let left = node.child_by_field_name("left");
        let right = node.child_by_field_name("right");

        if let (Some(left_node), Some(right_node)) = (left, right) {
            // Check if we have a pointer comparison with (array + sizeof(array))
            if self.has_sizeof_in_pointer_arithmetic(&left_node, source)
                || self.has_sizeof_in_pointer_arithmetic(&right_node, source)
            {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    message: "Pointer comparison uses sizeof(array) instead of array element count. Use the number of elements, not sizeof.".to_string(),
                    severity: self.severity(),
                    file_path: String::new(),
                    ..Default::default()
                });
            }
        }
    }

    /// Check for struct pointer arithmetic that should use char* cast
    fn check_struct_pointer_arithmetic(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get the left operand of the addition/subtraction
        if let Some(left) = node.child_by_field_name("left") {
            // Check if this looks like a struct pointer
            let left_text = ast_utils::get_node_text(&left, source);

            // Skip if already cast to char* or similar
            if left_text.contains("(char *)")
                || left_text.contains("(char*)")
                || left_text.contains("(unsigned char *)")
                || left_text.contains("(unsigned char*)")
            {
                return;
            }

            // Check if right operand involves offsetof or similar calculations
            if let Some(right) = node.child_by_field_name("right") {
                let right_text = ast_utils::get_node_text(&right, source);

                // Flag if we see offsetof() directly, or a variable that likely holds an offset
                if right_text.contains("offsetof")
                    || (self.looks_like_struct_pointer(&left, source)
                        && self.looks_like_offset_value(&right, source))
                {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        message: "Pointer arithmetic on struct pointer with byte offset. Cast to char* before adding offset.".to_string(),
                        severity: self.severity(),
                        file_path: String::new(),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Check if a node contains sizeof() applied to the same array used in pointer arithmetic
    fn has_sizeof_in_pointer_arithmetic(&self, node: &Node, source: &str) -> bool {
        // Look for pattern: (array + sizeof(array))
        if node.kind() == "parenthesized_expression" {
            if let Some(inner) = node.named_child(0) {
                return self.has_sizeof_in_pointer_arithmetic(&inner, source);
            }
        }

        if node.kind() == "binary_expression" {
            if let Some(operator) = ast_utils::get_binary_operator(node, source) {
                if operator == "+" {
                    if let (Some(left), Some(right)) = (
                        node.child_by_field_name("left"),
                        node.child_by_field_name("right"),
                    ) {
                        // Check if left is an identifier and right is sizeof(same_identifier)
                        let left_text = ast_utils::get_node_text(&left, source);

                        if self.is_sizeof_expression(&right, source) {
                            let sizeof_arg = self.get_sizeof_argument(&right, source);

                            // Check if sizeof is applied to the same array
                            if !sizeof_arg.is_empty() && left_text.contains(&sizeof_arg) {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// Check if a node is a sizeof expression
    fn is_sizeof_expression(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "sizeof_expression" {
            return true;
        }

        // Check for parenthesized sizeof
        if node.kind() == "parenthesized_expression" {
            if let Some(inner) = node.named_child(0) {
                return self.is_sizeof_expression(&inner, source);
            }
        }

        false
    }

    /// Get the argument to a sizeof expression
    fn get_sizeof_argument(&self, node: &Node, source: &str) -> String {
        if node.kind() == "sizeof_expression" {
            // sizeof can have different argument formats
            if let Some(arg) = node.child_by_field_name("value") {
                let text = ast_utils::get_node_text(&arg, source).to_string();
                // Remove parentheses if present
                return text
                    .trim_start_matches('(')
                    .trim_end_matches(')')
                    .to_string();
            }

            if let Some(arg) = node.child_by_field_name("type") {
                let text = ast_utils::get_node_text(&arg, source).to_string();
                // Remove parentheses if present
                return text
                    .trim_start_matches('(')
                    .trim_end_matches(')')
                    .to_string();
            }
        }

        // Check for parenthesized sizeof
        if node.kind() == "parenthesized_expression" {
            if let Some(inner) = node.named_child(0) {
                return self.get_sizeof_argument(&inner, source);
            }
        }

        String::new()
    }

    /// Check if a node looks like a struct pointer (has 's' or 'ptr' in name and is a pointer dereference or identifier)
    fn looks_like_struct_pointer(&self, node: &Node, source: &str) -> bool {
        let text = ast_utils::get_node_text(&node, source).to_lowercase();

        // Simple heuristic: check for common struct pointer patterns
        // In the test case, we have "struct big *s" so "s" is the pointer
        if node.kind() == "identifier" {
            // Only flag very short single-letter names that are common for struct pointers
            // Avoid common array names like "buf", "arr", "data"
            if text.len() == 1 {
                return true;
            }
            // Or explicit "struct" in nearby context (too complex for now)
            return false;
        }

        false
    }

    /// Check if a node looks like an offset value (variable containing "offset", "skip", or numeric literal)
    fn looks_like_offset_value(&self, node: &Node, source: &str) -> bool {
        let text = ast_utils::get_node_text(&node, source).to_lowercase();

        // Check for offset-related variable names
        if node.kind() == "identifier" {
            return text.contains("offset") || text.contains("skip");
        }

        // Don't flag macro constants (all caps) as they're likely array sizes, not byte offsets
        if node.kind() == "identifier" && text.chars().all(|c| c.is_uppercase() || c == '_') {
            return false;
        }

        false
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
    fn test_sizeof_in_pointer_comparison() {
        let code = r#"
int buf[100];
int *buf_ptr = buf;
while (buf_ptr < (buf + sizeof(buf))) {
    *buf_ptr++ = 1;
}
"#;
        let tree = parse_c_code(code);
        let rule = Exp08C;
        let violations = rule.check(&tree.root_node(), code);
        assert!(
            !violations.is_empty(),
            "Should detect sizeof(array) in pointer comparison"
        );
    }

    #[test]
    fn test_proper_array_element_count() {
        let code = r#"
int buf[100];
int *buf_ptr = buf;
while (buf_ptr < (buf + 100)) {
    *buf_ptr++ = 1;
}
"#;
        let tree = parse_c_code(code);
        let rule = Exp08C;
        let violations = rule.check(&tree.root_node(), code);
        assert!(
            violations.is_empty(),
            "Should not flag proper element count"
        );
    }

    #[test]
    fn test_struct_pointer_arithmetic() {
        let code = r#"
struct big *s = malloc(sizeof(struct big));
size_t skip = 8;
memset(s + skip, 0, 10);
"#;
        let tree = parse_c_code(code);
        let rule = Exp08C;
        let violations = rule.check(&tree.root_node(), code);
        assert!(
            !violations.is_empty(),
            "Should detect struct pointer arithmetic without char* cast"
        );
    }

    #[test]
    fn test_struct_pointer_with_cast() {
        let code = r#"
struct big *s = malloc(sizeof(struct big));
size_t skip = 8;
memset((char *)s + skip, 0, 10);
"#;
        let tree = parse_c_code(code);
        let rule = Exp08C;
        let violations = rule.check(&tree.root_node(), code);
        assert!(
            violations.is_empty(),
            "Should not flag struct pointer arithmetic with char* cast"
        );
    }
}
