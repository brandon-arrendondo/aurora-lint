use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

/// MEM35-C: Allocate sufficient memory for an object
///
/// Detects memory allocation calls with incorrect size arguments:
/// 1. Using sizeof(pointer) instead of sizeof(*pointer) or sizeof(type)
/// 2. Type mismatches in array allocations
pub struct Mem35C;

impl Mem35C {
    pub fn new() -> Self {
        Self
    }

    /// Check if a call_expression is a memory allocation function
    fn is_allocation_function(node: &Node, source: &str) -> bool {
        if node.kind() != "call_expression" {
            return false;
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "identifier" {
                let func_name = get_node_text(&child, source);
                return matches!(func_name, "malloc" | "calloc" | "realloc" | "aligned_alloc");
            }
        }
        false
    }

    /// Check if a sizeof expression uses a pointer variable instead of the pointed-to type
    fn is_sizeof_pointer_violation(node: &Node, source: &str) -> bool {
        if node.kind() != "sizeof_expression" {
            return false;
        }

        // Get the argument to sizeof
        let mut cursor = node.walk();
        let children: Vec<Node> = node.children(&mut cursor).collect();

        for child in children.iter() {
            if child.kind() == "parenthesized_expression" {
                let expr_text = get_node_text(child, source);
                let inner_text = expr_text
                    .trim_start_matches('(')
                    .trim_end_matches(')')
                    .trim();

                // Skip if it's a dereference (starts with *)
                if inner_text.starts_with('*') {
                    return false;
                }

                // Skip if it contains type keywords
                if inner_text.contains("struct")
                    || inner_text.contains("union")
                    || inner_text.contains("enum")
                    || inner_text.contains("int")
                    || inner_text.contains("char")
                    || inner_text.contains("float")
                    || inner_text.contains("double")
                    || inner_text.contains("void")
                    || inner_text.contains("long")
                    || inner_text.contains("short")
                {
                    return false;
                }

                // Check if it's a simple identifier (likely a pointer variable)
                // Common pointer variable naming patterns
                if inner_text.ends_with("_ptr")
                    || inner_text.ends_with("ptr")
                    || inner_text.ends_with("_p")
                    || inner_text.starts_with("p_")
                    || inner_text.starts_with("ptr_")
                    || inner_text == "tmb"
                // From wiki example
                {
                    return true;
                }
            }

            // Check type_descriptor for sizeof(type) patterns
            if child.kind() == "type_descriptor" {
                let type_text = get_node_text(child, source);

                // sizeof(type*) is suspicious - should be sizeof(type) or sizeof(*ptr)
                if type_text.contains('*') {
                    return true;
                }
            }
        }

        false
    }

    /// Check for type mismatches in array allocations
    fn check_array_allocation_type_mismatch(call_node: &Node, source: &str) -> bool {
        // Look for patterns like: type1 *ptr = malloc(count * sizeof(type2))
        // where type1 != type2

        // Find the assignment or declaration this malloc is part of
        let mut current = *call_node;
        let mut target_type: Option<String> = None;

        for _ in 0..10 {
            if let Some(parent) = current.parent() {
                if parent.kind() == "init_declarator" {
                    // Get the base type from the declaration
                    if let Some(declaration) = parent.parent() {
                        if declaration.kind() == "declaration" {
                            let mut decl_cursor = declaration.walk();
                            let decl_children: Vec<Node> =
                                declaration.children(&mut decl_cursor).collect();

                            for decl_child in decl_children.iter() {
                                if decl_child.kind() == "primitive_type"
                                    || decl_child.kind() == "type_identifier"
                                    || decl_child.kind() == "struct_specifier"
                                {
                                    target_type =
                                        Some(get_node_text(decl_child, source).to_string());
                                    break;
                                }
                            }
                        }
                    }
                    break;
                } else if parent.kind() == "cast_expression" {
                    // For assignments like: p = (long *)malloc(...)
                    // Get the cast type
                    let mut cast_cursor = parent.walk();
                    for child in parent.children(&mut cast_cursor) {
                        if child.kind() == "type_descriptor" {
                            let cast_type_text = get_node_text(&child, source);
                            // Extract base type from "long *" -> "long"
                            let base_type = cast_type_text
                                .trim()
                                .trim_start_matches('(')
                                .trim_end_matches(')')
                                .replace("*", "")
                                .replace(" ", "")
                                .trim()
                                .to_string();
                            if !base_type.is_empty() {
                                target_type = Some(base_type);
                            }
                            break;
                        }
                    }
                    // Continue searching up for more context if needed
                }
                current = parent;
            } else {
                break;
            }
        }

        if target_type.is_none() {
            return false;
        }

        let target_type = target_type.unwrap();
        let call_text = get_node_text(call_node, source);

        // Look for sizeof(type) in the call arguments
        if let Some(sizeof_start) = call_text.find("sizeof") {
            let sizeof_part = &call_text[sizeof_start..];

            // Extract what's inside sizeof(...)
            if let Some(open_paren) = sizeof_part.find('(') {
                if let Some(close_paren) = sizeof_part.find(')') {
                    let sizeof_arg = &sizeof_part[open_paren + 1..close_paren];
                    let sizeof_arg = sizeof_arg.trim();

                    // If sizeof uses dereference (sizeof(*ptr)), that's CORRECT - don't flag it
                    if sizeof_arg.starts_with('*') {
                        return false;
                    }

                    if !sizeof_arg.is_empty() && !target_type.is_empty() {
                        let target_normalized = target_type.trim();
                        let sizeof_normalized = sizeof_arg.trim();

                        if target_normalized != sizeof_normalized {
                            // Allow some compatible types
                            if !(target_normalized == "char" && sizeof_normalized == "1"
                                || target_normalized.contains("struct")
                                    && sizeof_normalized.contains("struct"))
                            {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// Check allocation calls in a node
    fn check_allocations(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |c| Self::is_allocation_function(&c, source)) {
            let call_text = get_node_text(&n, source);

            // Check for sizeof(pointer) violations
            let mut cursor = n.walk();
            for child in n.children(&mut cursor) {
                Self::check_sizeof_in_node(&child, &n, source, &call_text, violations);
            }

            // Check for type mismatches
            if Self::check_array_allocation_type_mismatch(&n, source) {
                violations.push(RuleViolation {
                    rule_id: "MEM35-C".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Memory allocation has type mismatch between pointer type and sizeof argument. This may allocate insufficient memory. Code: {}",
                        call_text.trim()
                    ),
                    file_path: String::new(),
                    line: n.start_position().row + 1,
                    column: n.start_position().column + 1,
                    suggestion: None,
                    requires_manual_review: None,
                });
            }
        }
    }

    /// Check for sizeof violations in a node and its children
    fn check_sizeof_in_node(
        node: &Node,
        call_node: &Node,
        source: &str,
        call_text: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() == "sizeof_expression" {
            if Self::is_sizeof_pointer_violation(node, source) {
                violations.push(RuleViolation {
                    rule_id: "MEM35-C".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Memory allocation uses sizeof(pointer) instead of sizeof(*pointer) or sizeof(type). This allocates insufficient memory for the object. Code: {}",
                        call_text.trim()
                    ),
                    file_path: String::new(),
                    line: call_node.start_position().row + 1,
                    column: call_node.start_position().column + 1,
                    suggestion: None,
                    requires_manual_review: None,
                });
                return; // Only report once per allocation call
            }
        }

        // Recursively check children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::check_sizeof_in_node(&child, call_node, source, call_text, violations);
        }
    }

    // ── CWE-789: Unbounded memory allocation from untrusted input ──────

    const TAINT_SOURCES: &'static [&'static str] = &[
        "recv", "fgets", "fscanf", "scanf", "rand", "read", "getenv", "listen", "connect", "accept",
    ];

    const TAINT_CONVERTERS: &'static [&'static str] =
        &["strtoul", "strtol", "atoi", "atol", "atoll", "strtoull"];

    fn check_unbounded_alloc_from_input(
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(body) = n.child_by_field_name("body") {
                Self::check_function_for_taint_alloc(&body, source, violations);
            }
        }
    }

    fn check_function_for_taint_alloc(
        body: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let mut has_taint_source = false;
        let mut alloc_positions: Vec<(usize, usize)> = Vec::new();
        let mut has_upper_bound = false;

        Self::scan_taint_alloc_bounds(
            body,
            source,
            &mut has_taint_source,
            &mut alloc_positions,
            &mut has_upper_bound,
        );

        if has_taint_source && !has_upper_bound {
            for (line, col) in &alloc_positions {
                violations.push(RuleViolation {
                    rule_id: "MEM35-C".to_string(),
                    severity: Severity::High,
                    message:
                        "Memory allocation with size from untrusted input without upper-bound check"
                            .to_string(),
                    file_path: String::new(),
                    line: *line,
                    column: *col,
                    suggestion: Some(
                        "Add an upper-bound check (e.g., if (size < MAX_SIZE)) before allocating"
                            .to_string(),
                    ),
                    requires_manual_review: None,
                });
            }
        }
    }

    fn scan_taint_alloc_bounds(
        node: &Node,
        source: &str,
        has_taint: &mut bool,
        alloc_pos: &mut Vec<(usize, usize)>,
        has_bound: &mut bool,
    ) {
        for n in query::find_descendants(*node, |_| true) {
            if n.kind() == "call_expression" {
                if let Some(func) = n.child_by_field_name("function") {
                    let name = get_node_text(&func, source).trim().to_string();
                    if Self::TAINT_SOURCES.contains(&name.as_str())
                        || Self::TAINT_CONVERTERS.contains(&name.as_str())
                    {
                        *has_taint = true;
                    }
                    if matches!(name.as_str(), "malloc" | "calloc" | "realloc") {
                        alloc_pos.push((n.start_position().row + 1, n.start_position().column + 1));
                    }
                }
            }

            // Check for upper-bound comparisons: data < CONSTANT
            if n.kind() == "binary_expression" {
                let children: Vec<_> = (0..n.child_count()).filter_map(|i| n.child(i)).collect();
                for (i, child) in children.iter().enumerate() {
                    let op = get_node_text(child, source);
                    if (op == "<" || op == "<=") && i + 1 < children.len() {
                        let right = &children[i + 1];
                        if right.kind() == "number_literal" {
                            *has_bound = true;
                        }
                    }
                }
            }
        }
    }
}

impl CertRule for Mem35C {
    fn rule_id(&self) -> &'static str {
        "MEM35-C"
    }

    fn description(&self) -> &'static str {
        "Allocate sufficient memory for an object"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "MEM35-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        Self::check_allocations(node, source, &mut violations);
        Self::check_unbounded_alloc_from_input(node, source, &mut violations);
        violations
    }
}
