use crate::manifest::{RuleCategory, Severity};
use crate::rules::{CertRule, RuleViolation};
use crate::utility::cert_c::ast_utils::get_node_text;
use streaming_iterator::StreamingIterator;
use tree_sitter::{Node, Query, QueryCursor};

/// EXP42-C: Do not compare padding data
///
/// Detects uses of memcmp() or similar functions to compare structures
/// that may contain padding bytes with indeterminate values.
///
/// # Violations
/// - Using memcmp() to compare entire structs (including padding)
/// - Comparing structures byte-by-byte when padding may be present
///
/// # Compliant Code
/// - Compare struct members individually
/// - Use #pragma pack to eliminate padding (exception case)
pub struct Exp42C;

impl CertRule for Exp42C {
    fn rule_id(&self) -> &'static str {
        "EXP42-C"
    }

    fn description(&self) -> &'static str {
        "Do not compare padding data"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "EXP42-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Query to find call_expression nodes for memcmp
        let query_str = r#"
            (call_expression
                function: (identifier) @func_name
                arguments: (argument_list) @args
            ) @call
        "#;

        let language = crate::parser::c_language();
        let query = Query::new(&language, query_str).expect("Invalid query");
        let mut query_cursor = QueryCursor::new();
        // tree-sitter 0.25: `matches` returns a StreamingIterator, not a plain
        // Iterator — drive it with `while let Some(m) = it.next()`.
        let mut matches = query_cursor.matches(&query, *node, source.as_bytes());

        while let Some(m) = matches.next() {
            let mut func_name_node = None;
            let mut args_node = None;
            let mut call_node = None;

            for capture in m.captures {
                let capture_name = &query.capture_names()[capture.index as usize];
                match &**capture_name {
                    "func_name" => func_name_node = Some(capture.node),
                    "args" => args_node = Some(capture.node),
                    "call" => call_node = Some(capture.node),
                    _ => {}
                }
            }

            if let (Some(func_node), Some(args), Some(call)) =
                (func_name_node, args_node, call_node)
            {
                let func_name = get_node_text(&func_node, source);

                // Check if this is memcmp or similar comparison functions
                if func_name == "memcmp" || func_name == "memcmp_s" {
                    // Analyze arguments to detect struct comparison
                    if is_struct_comparison(&args, source) {
                        let start_pos = call.start_position();

                        violations.push(RuleViolation {
                            rule_id: "EXP42-C".to_string(),
                            severity: Severity::Medium,
                            message: format!(
                                "Comparing padding data using {}(). Padding bytes in structures have indeterminate values and should not be compared. Consider comparing struct members individually instead, or use #pragma pack to eliminate padding.",
                                func_name
                            ),
                            file_path: String::new(), // Will be filled by caller
                            line: start_pos.row + 1,
                            column: start_pos.column + 1,
                            suggestion: Some(
                                "Compare struct members individually instead of using memcmp()".to_string()
                            ),
                            requires_manual_review: None,
                        });
                    }
                }
            }
        }

        violations
    }
}

/// Determines if the arguments to a memcmp-like function suggest a struct comparison
fn is_struct_comparison(args_node: &Node, source: &str) -> bool {
    let mut cursor = args_node.walk();
    let mut arguments = Vec::new();

    // Collect all argument nodes
    for child in args_node.children(&mut cursor) {
        if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
            arguments.push(child);
        }
    }

    // memcmp signature: int memcmp(const void *ptr1, const void *ptr2, size_t num)
    // We need at least 3 arguments
    if arguments.len() < 3 {
        return false;
    }

    // Check if the third argument (size) is sizeof(struct ...)
    // This is a strong indicator of struct comparison
    let size_arg = arguments[2];
    if has_sizeof_struct(&size_arg, source) {
        return true;
    }

    // Additional heuristic: Check if arguments look like struct pointers
    // by checking for cast expressions or address-of operators on struct types
    for i in 0..2 {
        if i < arguments.len() && looks_like_struct_pointer(&arguments[i], source) {
            // If we find struct pointer arguments and the size looks suspicious,
            // flag it as a potential violation
            if looks_like_sizeof_usage(&size_arg, source) {
                return true;
            }
        }
    }

    false
}

/// Checks if a node contains sizeof with a struct type
fn has_sizeof_struct(node: &Node, source: &str) -> bool {
    let text = get_node_text(node, source);

    // Look for "sizeof" followed by "struct" pattern
    if text.contains("sizeof") && text.contains("struct") {
        return true;
    }

    // Also check child nodes for sizeof_expression
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "sizeof_expression" {
            // Check if the type is a struct
            let sizeof_text = get_node_text(&child, source);
            if sizeof_text.contains("struct") {
                return true;
            }

            // Look for struct_specifier or type_identifier that might reference a struct
            let mut sizeof_cursor = child.walk();
            for sizeof_child in child.children(&mut sizeof_cursor) {
                if sizeof_child.kind() == "struct_specifier"
                    || sizeof_child.kind() == "type_identifier"
                {
                    return true;
                }
            }
        }

        // Recursively check child nodes
        if has_sizeof_struct(&child, source) {
            return true;
        }
    }

    false
}

/// Checks if a size argument looks like sizeof usage (heuristic)
fn looks_like_sizeof_usage(node: &Node, source: &str) -> bool {
    let text = get_node_text(node, source);
    text.contains("sizeof")
}

/// Heuristic to detect if a node looks like a struct pointer
fn looks_like_struct_pointer(node: &Node, source: &str) -> bool {
    // Check for cast expressions to struct types
    if node.kind() == "cast_expression" {
        let text = get_node_text(node, source);
        if text.contains("struct") {
            return true;
        }
    }

    // Check for address-of operator (&) on identifiers
    if node.kind() == "unary_expression" {
        let text = get_node_text(node, source);
        if text.starts_with('&') {
            return true;
        }
    }

    // Check for pointer_expression (->)
    if node.kind() == "pointer_expression" {
        return true;
    }

    // Recursively check children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if looks_like_struct_pointer(&child, source) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_id() {
        let rule = Exp42C;
        assert_eq!(rule.rule_id(), "EXP42-C");
    }

    #[test]
    fn test_description() {
        let rule = Exp42C;
        assert_eq!(rule.description(), "Do not compare padding data");
    }
}
