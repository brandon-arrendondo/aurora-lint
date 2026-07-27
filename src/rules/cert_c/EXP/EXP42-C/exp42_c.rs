use crate::manifest::{RuleCategory, Severity};
use crate::rules::{CertRule, RuleViolation};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
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
                    if is_struct_comparison(&args, source)
                        && !is_packed_struct_comparison(node, &args, source)
                    {
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

/// EXP42-C's own exception: if the struct type being compared was defined
/// under `#pragma pack(push, 1)` / `#pragma pack(1)` (with no intervening
/// `#pragma pack(pop)`/reset before the definition), the compiler emits no
/// inter-member padding, so a memcmp() over the whole struct is safe.
fn is_packed_struct_comparison(root: &Node, args_node: &Node, source: &str) -> bool {
    let Some(struct_name) = extract_struct_type_name(args_node, source) else {
        return false;
    };
    let Some(struct_def) = query::find_first_descendant(*root, |n| {
        n.kind() == "struct_specifier"
            && n.child_by_field_name("body").is_some()
            && n.child_by_field_name("name")
                .map(|name| get_node_text(&name, source) == struct_name)
                .unwrap_or(false)
    }) else {
        return false;
    };
    is_pack_one_active_before(root, struct_def.start_byte(), source)
}

/// Find the struct type name referenced by a memcmp() argument list, either
/// via `sizeof(struct NAME)` or a `(struct NAME *)`/`const struct NAME *`
/// pointer argument.
fn extract_struct_type_name(args_node: &Node, source: &str) -> Option<String> {
    query::find_first_descendant(*args_node, |n| n.kind() == "struct_specifier").and_then(
        |struct_ref| {
            struct_ref
                .child_by_field_name("name")
                .map(|name| get_node_text(&name, source).to_string())
        },
    )
}

/// Scan `#pragma pack` directives (as `preproc_call` nodes) that appear
/// before `byte_pos`, tracking whether a pack-to-1 is currently active.
/// Approximates the push/pop stack as a single flag, which is sufficient
/// for the common (non-nested) `#pragma pack(push, 1) ... #pragma pack(pop)`
/// idiom.
fn is_pack_one_active_before(root: &Node, byte_pos: usize, source: &str) -> bool {
    let mut active = false;
    for pc in query::find_descendants_of_kind(*root, "preproc_call") {
        if pc.start_byte() >= byte_pos {
            break;
        }
        let text = get_node_text(&pc, source);
        if !text.contains("pack") {
            continue;
        }
        if text.contains("pop") {
            active = false;
        } else if text.contains('1') {
            active = true;
        }
    }
    active
}

/// Checks if a node contains sizeof with a struct type
fn has_sizeof_struct(node: &Node, source: &str) -> bool {
    let text = get_node_text(node, source);

    // Look for "sizeof" followed by "struct" pattern
    if text.contains("sizeof") && text.contains("struct") {
        return true;
    }

    // Also check descendant sizeof_expression nodes
    query::find_first_descendant(*node, |n| {
        if n.kind() != "sizeof_expression" {
            return false;
        }
        // Check if the type is a struct
        let sizeof_text = get_node_text(&n, source);
        if sizeof_text.contains("struct") {
            return true;
        }
        // Look for struct_specifier or type_identifier that might reference a struct
        let mut cursor = n.walk();
        let has_struct_child = n
            .children(&mut cursor)
            .any(|c| c.kind() == "struct_specifier" || c.kind() == "type_identifier");
        has_struct_child
    })
    .is_some()
}

/// Checks if a size argument looks like sizeof usage (heuristic)
fn looks_like_sizeof_usage(node: &Node, source: &str) -> bool {
    let text = get_node_text(node, source);
    text.contains("sizeof")
}

/// Heuristic to detect if a node looks like a struct pointer
fn looks_like_struct_pointer(node: &Node, source: &str) -> bool {
    query::find_first_descendant(*node, |n| {
        // Check for cast expressions to struct types
        if n.kind() == "cast_expression" {
            let text = get_node_text(&n, source);
            if text.contains("struct") {
                return true;
            }
        }

        // Check for address-of operator (&) on identifiers
        if n.kind() == "unary_expression" {
            let text = get_node_text(&n, source);
            if text.starts_with('&') {
                return true;
            }
        }

        // Check for pointer_expression (->)
        if n.kind() == "pointer_expression" {
            return true;
        }

        false
    })
    .is_some()
}
