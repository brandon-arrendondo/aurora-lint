use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Fio17C;

impl CertRule for Fio17C {
    fn rule_id(&self) -> &'static str {
        "FIO17-C"
    }

    fn description(&self) -> &'static str {
        "Never use fread() on a character array to read character data without explicitly accounting for the missing null terminator"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        self.rule_id()
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(root, source, violations);
    }
}

impl Fio17C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func) = n.child_by_field_name("function") {
                let func_name = get_node_text(&func, source);
                if func_name == "fread" {
                    // Check if buffer appears to be used for string data without null terminator handling
                    if self.is_unsafe_fread(&n, source) {
                        let line = n.start_position().row + 1;
                        let column = n.start_position().column + 1;

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            message: "fread() used without explicitly accounting for null terminator in character buffer".to_string(),
                            file_path: String::new(),
                            line,
                            column,
                            suggestion: Some("Ensure buffer size accounts for null terminator, or explicitly add null terminator after fread()".to_string()),
                            requires_manual_review: Some(true),
                        });
                    }
                }
            }
        }
    }

    fn is_unsafe_fread(&self, node: &Node, source: &str) -> bool {
        // Get the buffer argument (first argument to fread)
        if let Some(args) = node.child_by_field_name("arguments") {
            if let Some(buffer_arg) = self.get_nth_argument(&args, 0) {
                let buffer_name = get_node_text(&buffer_arg, source);

                // Look for patterns that suggest missing null terminator handling
                // The key issue: fread doesn't add null terminator, but buffer may be used as string
                // We flag fread on character buffers when there's no explicit null terminator addition

                // Check if there's a null terminator added after this fread
                // OR if there's a length check before fread that suggests size validation
                if !self.has_null_terminator_after(node, &buffer_name, source)
                    && !self.has_size_check_before(node, source)
                {
                    return true;
                }
            }
        }
        false
    }

    fn has_size_check_before(&self, fread_node: &Node, source: &str) -> bool {
        // Look for "length != size" or similar size validation before fread
        let fread_start = fread_node.start_byte();
        let preceding_source = &source[..fread_start];

        // Simple check for size validation patterns
        if preceding_source.contains("!= size")
            || preceding_source.contains("length != size")
            || preceding_source.contains("size != length")
        {
            return true;
        }

        false
    }

    fn has_null_terminator_after(
        &self,
        fread_node: &Node,
        buffer_name: &str,
        source: &str,
    ) -> bool {
        // Look for patterns like: buffer[size] = '\0' or buffer[...] = 0 after fread
        // This is a simplified check - in a real implementation we'd track control flow

        let fread_end = fread_node.end_byte();
        let remaining_source = &source[fread_end..];

        // Look for explicit null terminator assignment
        // Patterns: buffer[...] = '\0'; or buffer[...] = 0;
        let _patterns = [
            format!("{}[", buffer_name),
            String::from("= '\\0'"),
            String::from("= 0"),
        ];

        // Simple check: if we see buffer[...] = '\0' or similar within next 200 chars
        if remaining_source.len() > 200 {
            let check_window = &remaining_source[..200];
            if check_window.contains(&format!("{}[", buffer_name)) {
                if check_window.contains("'\\0'") || check_window.contains("= 0;") {
                    return true;
                }
            }
        } else if remaining_source.contains(&format!("{}[", buffer_name)) {
            if remaining_source.contains("'\\0'") || remaining_source.contains("= 0;") {
                return true;
            }
        }

        false
    }

    fn get_nth_argument<'a>(&self, arguments: &Node<'a>, n: usize) -> Option<Node<'a>> {
        let mut cursor = arguments.walk();
        let mut current_arg = 0;

        for child in arguments.children(&mut cursor) {
            if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                if current_arg == n {
                    return Some(child);
                }
                current_arg += 1;
            }
        }
        None
    }
}
