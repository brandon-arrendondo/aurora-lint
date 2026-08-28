//! Shared helpers for arithmetic-overflow-detection rules (`INT30-C`,
//! `INT32-C`, and one primitive each for `INT10-C`).
//!
//! Task 481's ruleset-wide duplication sweep found `INT30-C` (~2760 lines)
//! and `INT32-C` (~2920 lines) independently defining ~20 identically-named
//! private helpers for the same sub-problems (building a local
//! variable/parameter type map, extracting operand identifiers, resolving
//! an identifier's originating call, etc.) -- the single largest duplicated
//! surface found in that sweep. Filed and worked as task 490.
//!
//! **Not everything with a matching name lives here.** A follow-up audit
//! (task 490) found that the `has_overflow_check_*` family and
//! `is_small_increment_of_opaque` only *look* duplicated: `INT30-C`'s
//! versions detect unsigned-wraparound guard idioms (`UINT_MAX`/`SIZE_MAX`
//! thresholds) and `INT32-C`'s detect signed-overflow guard idioms
//! (`INT_MAX`/`INT_MIN`/`LONG_MAX`/`LONG_MIN`) -- two independently correct,
//! deliberately different pattern sets for two different overflow
//! directions. Those stay rule-local; folding them in here would require
//! designing a genuinely parameterized guard-detection engine, not a
//! mechanical extraction. `INT10-C` used to keep its own, simpler
//! `collect_variable_types` duplicate; task 570 found it silently dropped
//! every bare (non-`init_declarator`, non-pointer, non-array) comma-list
//! declarator -- e.g. `u32 size, hash;` -- from the type map, misflagging
//! provably-unsigned `%` operands as signed. `INT10-C` now calls this
//! module's version directly instead of maintaining a parallel, buggier one.

use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

/// Build a `{variable/parameter name -> type string}` map from a function's
/// parameters and local declarations. Pointer-typed declarators are recorded
/// as `"<base type> *"`. Correctly unwraps a top-level `init_declarator`
/// (e.g. `int *p = malloc(...);`, where the declaration node's `declarator`
/// field IS the `init_declarator`, not a bare `pointer_declarator`) -- a
/// case `INT32-C`'s pre-migration version missed, silently recording such a
/// variable as non-pointer.
pub fn collect_variable_types(node: &Node, source: &str) -> HashMap<String, String> {
    let mut type_map = HashMap::new();

    for func in query::find_descendants_of_kind(*node, "function_definition") {
        if let Some(declarator) = func.child_by_field_name("declarator") {
            collect_params_from_declarator(&declarator, source, &mut type_map);
        }
        if let Some(body) = func.child_by_field_name("body") {
            collect_local_declarations(&body, source, &mut type_map);
        }
    }

    type_map
}

/// Collect `{name -> type}` entries for a `function_declarator`'s
/// parameters. Exposed separately from [`collect_variable_types`] because
/// `INT30-C` also calls it directly to build a params-only map for a single
/// function (e.g. checking whether two call arguments are both parameters).
pub fn collect_params_from_declarator(
    node: &Node,
    source: &str,
    type_map: &mut HashMap<String, String>,
) {
    for declarator in query::find_descendants_of_kind(*node, "function_declarator") {
        if let Some(params) = declarator.child_by_field_name("parameters") {
            for i in 0..params.child_count() {
                if let Some(param) = params.child(i) {
                    if param.kind() == "parameter_declaration" {
                        extract_type_and_name(&param, source, type_map);
                    }
                }
            }
        }
    }
}

fn collect_local_declarations(node: &Node, source: &str, type_map: &mut HashMap<String, String>) {
    for decl in query::find_descendants_of_kind(*node, "declaration") {
        extract_type_and_name(&decl, source, type_map);
    }
}

fn extract_type_and_name(node: &Node, source: &str, type_map: &mut HashMap<String, String>) {
    let mut type_text = String::new();

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "primitive_type" | "sized_type_specifier" | "type_identifier" => {
                    type_text = get_node_text(&child, source).to_string();
                }
                "struct_specifier" => {
                    type_text = get_node_text(&child, source).to_string();
                }
                _ => {}
            }
        }
    }

    if type_text.is_empty() {
        return;
    }

    // A `declaration` node's `declarator` field repeats once per
    // comma-separated declarator (e.g. `u32 size, hash;` has TWO
    // `declarator`-field children, both direct `identifier` nodes with no
    // `init_declarator`/`pointer_declarator` wrapper). `child_by_field_name`
    // only ever returns the first match, so a plain `if let` here silently
    // dropped every declarator after the first -- `children_by_field_name`
    // walks all of them.
    let mut cursor = node.walk();
    for declarator in node.children_by_field_name("declarator", &mut cursor) {
        if let Some(name) = extract_identifier_name(&declarator, source) {
            let full_type = if is_pointer_declarator_field(&declarator) {
                format!("{} *", type_text)
            } else {
                type_text.clone()
            };
            type_map.insert(name, full_type);
        }
    }
}

/// True if this declarator (or an `init_declarator` wrapping it) contains a
/// `pointer_declarator`, indicating the declared variable is a pointer
/// type. The `init_declarator` unwrap matters because a `declaration`
/// node's `declarator` field IS the `init_declarator` itself when there's
/// an initializer, not a bare `pointer_declarator`.
fn is_pointer_declarator_field(node: &Node) -> bool {
    if node.kind() == "pointer_declarator" {
        return true;
    }
    if node.kind() == "init_declarator" {
        if let Some(decl) = node.child_by_field_name("declarator") {
            return decl.kind() == "pointer_declarator";
        }
    }
    false
}

/// Resolve the bound identifier of a declarator, unwrapping one level of
/// `pointer_declarator`/`array_declarator`/`parenthesized_declarator`.
pub fn extract_identifier_name(node: &Node, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" => Some(get_node_text(node, source).to_string()),
        "pointer_declarator"
        | "array_declarator"
        | "parenthesized_declarator"
        | "init_declarator" => {
            if let Some(inner) = node.child_by_field_name("declarator") {
                extract_identifier_name(&inner, source)
            } else {
                None
            }
        }
        _ => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "identifier" {
                        return Some(get_node_text(&child, source).to_string());
                    }
                }
            }
            None
        }
    }
}

/// Collect the identifier names referenced by a binary/assignment/update
/// expression's `left`/`right`/`argument` fields (whichever are present).
pub fn extract_operand_names(node: &Node, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(left) = node.child_by_field_name("left") {
        collect_identifiers(&left, source, &mut names);
    }
    if let Some(right) = node.child_by_field_name("right") {
        collect_identifiers(&right, source, &mut names);
    }
    if let Some(arg) = node.child_by_field_name("argument") {
        collect_identifiers(&arg, source, &mut names);
    }
    names
}

/// Collect every distinct identifier name under `node`, preserving first-seen order.
pub fn collect_identifiers(node: &Node, source: &str, names: &mut Vec<String>) {
    for ident in query::find_descendants_of_kind(*node, "identifier") {
        let name = get_node_text(&ident, source).to_string();
        if !names.contains(&name) {
            names.push(name);
        }
    }
}

/// True if `text` contains `word` as a whole word (not a substring of a
/// longer identifier).
pub fn contains_word(text: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let mut start = 0;
    while let Some(pos) = text[start..].find(word) {
        let abs_pos = start + pos;
        let before_ok = abs_pos == 0
            || !text.as_bytes()[abs_pos - 1].is_ascii_alphanumeric()
                && text.as_bytes()[abs_pos - 1] != b'_';
        let after_pos = abs_pos + word.len();
        let after_ok = after_pos >= text.len()
            || !text.as_bytes()[after_pos].is_ascii_alphanumeric()
                && text.as_bytes()[after_pos] != b'_';
        if before_ok && after_ok {
            return true;
        }
        start = abs_pos + 1;
    }
    false
}

/// Within `scope`, walk statements strictly preceding `usage_node` (by
/// source row) looking for a declaration-with-initializer or assignment to
/// `var_name` whose RHS is a call expression, and return the called
/// function's name. Descends into nested blocks in call-then-continue
/// (depth-first) order, matching a naive recursive-then-sibling walk.
pub fn resolve_identifier_call_name(
    scope: &Node,
    var_name: &str,
    source: &str,
    usage_node: &Node,
) -> Option<String> {
    let usage_row = usage_node.start_position().row;
    let mut frames: Vec<(Node, usize)> = vec![(*scope, 0)];

    while let Some((cur_scope, start_idx)) = frames.pop() {
        let mut i = start_idx;
        while i < cur_scope.named_child_count() {
            let Some(child) = cur_scope.named_child(i) else {
                i += 1;
                continue;
            };
            if child.start_position().row >= usage_row {
                break;
            }
            if child.kind() == "declaration" {
                if let Some(declarator) = child.child_by_field_name("declarator") {
                    if declarator.kind() == "init_declarator" {
                        let decl_name = declarator
                            .child_by_field_name("declarator")
                            .map(|d| get_node_text(&d, source));
                        let init = declarator.child_by_field_name("value");
                        if decl_name == Some(var_name) {
                            if let Some(init_node) = init {
                                if init_node.kind() == "call_expression" {
                                    return init_node
                                        .child_by_field_name("function")
                                        .and_then(|f| f.utf8_text(source.as_bytes()).ok())
                                        .map(|s| s.trim().to_string());
                                }
                            }
                        }
                    }
                }
            }
            if child.kind() == "expression_statement" {
                if let Some(expr) = child.named_child(0) {
                    if expr.kind() == "assignment_expression" {
                        let lhs = expr.child_by_field_name("left");
                        let rhs = expr.child_by_field_name("right");
                        if let (Some(l), Some(r)) = (lhs, rhs) {
                            if get_node_text(&l, source) == var_name
                                && r.kind() == "call_expression"
                            {
                                return r
                                    .child_by_field_name("function")
                                    .and_then(|f| f.utf8_text(source.as_bytes()).ok())
                                    .map(|s| s.trim().to_string());
                            }
                        }
                    }
                }
            }
            if child.kind().starts_with("preproc_")
                || child.kind() == "compound_statement"
                || child.kind() == "if_statement"
                || child.kind() == "switch_statement"
                || child.kind() == "case_statement"
                || child.kind() == "for_statement"
                || child.kind() == "while_statement"
            {
                frames.push((cur_scope, i + 1));
                frames.push((child, 0));
                break;
            }
            i += 1;
        }
    }
    None
}

/// Within `scope`, walk statements strictly preceding `usage_node` (by
/// source row) looking for the *most recent* declaration-with-initializer
/// or assignment to `var_name`, and return its right-hand-side expression
/// node (whatever kind it is -- unlike `resolve_identifier_call_name`, not
/// restricted to a call). Used to resolve a bare identifier used as an
/// allocation-size argument back to the expression that actually computed
/// it (one assignment hop), so `to_len = from_len * 2U + 1U; ...;
/// malloc(to_len)` can be checked the same way as an inline
/// `malloc(from_len * 2U + 1U)`. Descends into nested blocks in the same
/// depth-first, call-then-continue order as `resolve_identifier_call_name`,
/// but keeps scanning past the first match so the last (most recent)
/// assignment before `usage_node` wins over an earlier one.
pub fn resolve_identifier_assignment_expr<'a>(
    scope: &Node<'a>,
    var_name: &str,
    source: &str,
    usage_node: &Node,
) -> Option<Node<'a>> {
    let usage_row = usage_node.start_position().row;
    let mut result: Option<Node<'a>> = None;
    let mut frames: Vec<(Node<'a>, usize)> = vec![(*scope, 0)];

    while let Some((cur_scope, start_idx)) = frames.pop() {
        let mut i = start_idx;
        while i < cur_scope.named_child_count() {
            let Some(child) = cur_scope.named_child(i) else {
                i += 1;
                continue;
            };
            if child.start_position().row >= usage_row {
                break;
            }
            if child.kind() == "declaration" {
                if let Some(declarator) = child.child_by_field_name("declarator") {
                    if declarator.kind() == "init_declarator" {
                        let decl_name = declarator
                            .child_by_field_name("declarator")
                            .map(|d| get_node_text(&d, source));
                        if decl_name == Some(var_name) {
                            if let Some(init_node) = declarator.child_by_field_name("value") {
                                result = Some(init_node);
                            }
                        }
                    }
                }
            }
            if child.kind() == "expression_statement" {
                if let Some(expr) = child.named_child(0) {
                    if expr.kind() == "assignment_expression" {
                        let lhs = expr.child_by_field_name("left");
                        let rhs = expr.child_by_field_name("right");
                        if let (Some(l), Some(r)) = (lhs, rhs) {
                            if get_node_text(&l, source) == var_name {
                                result = Some(r);
                            }
                        }
                    }
                }
            }
            if child.kind().starts_with("preproc_")
                || child.kind() == "compound_statement"
                || child.kind() == "if_statement"
                || child.kind() == "switch_statement"
                || child.kind() == "case_statement"
                || child.kind() == "for_statement"
                || child.kind() == "while_statement"
            {
                frames.push((cur_scope, i + 1));
                frames.push((child, 0));
                break;
            }
            i += 1;
        }
    }
    result
}

/// `"++"`/`"--"`/`"unknown"` depending on which appears in `node`'s text.
pub fn get_update_operator(node: &Node, source: &str) -> String {
    let text = get_node_text(node, source);
    if text.contains("++") {
        "++".to_string()
    } else if text.contains("--") {
        "--".to_string()
    } else {
        "unknown".to_string()
    }
}

/// Walk strictly upward from `node` (never checking `node` itself) to find
/// the nearest enclosing `function_definition`. Distinct from
/// `ast_utils::find_containing_function`, which treats `node` itself as a
/// match if it's already a `function_definition`.
pub fn enclosing_function_definition<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "function_definition" {
            return Some(parent);
        }
        current = parent.parent();
    }
    None
}

/// True for the fixed-width unsigned typedefs `u8`/`u16`/`u32`/`u64`/`u128`
/// (Rust-style short aliases sometimes used in C via typedef, not the C11
/// `uintN_t` family).
pub fn is_short_unsigned_typedef(s: &str) -> bool {
    matches!(s, "u8" | "u16" | "u32" | "u64" | "u128")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse_c_code(code: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let language = crate::parser::c_language();
        parser.set_language(&language).unwrap();
        parser.parse(code, None).unwrap()
    }

    #[test]
    fn contains_word_is_word_boundary_aware() {
        assert!(contains_word("if (x > 0)", "x"));
        assert!(!contains_word("if (xyz > 0)", "x"));
    }

    #[test]
    fn short_unsigned_typedef() {
        assert!(is_short_unsigned_typedef("u32"));
        assert!(!is_short_unsigned_typedef("uint32_t"));
    }

    #[test]
    fn collect_variable_types_marks_init_declarator_pointer() {
        // Regression test for the bug this consolidation fixed: a single
        // declarator with an initializer (`declarator` field IS the
        // init_declarator itself) must still be recorded as a pointer type.
        let tree = parse_c_code("void f(void) { int *p = get_ptr(); }");
        let type_map =
            collect_variable_types(&tree.root_node(), "void f(void) { int *p = get_ptr(); }");
        assert_eq!(type_map.get("p").map(|s| s.as_str()), Some("int *"));
    }

    #[test]
    fn get_update_operator_detects_increment_and_decrement() {
        let src = "void f(void) { int i = 0; i++; i--; }";
        let tree = parse_c_code(src);
        let mut found = Vec::new();
        for n in query::find_descendants_of_kind(tree.root_node(), "update_expression") {
            found.push(get_update_operator(&n, src));
        }
        assert_eq!(found, vec!["++".to_string(), "--".to_string()]);
    }

    #[test]
    fn enclosing_function_definition_is_strict_ancestor() {
        let src = "void f(void) { int i = 0; }";
        let tree = parse_c_code(src);
        let decl = query::find_descendants_of_kind(tree.root_node(), "declaration")
            .into_iter()
            .next()
            .unwrap();
        assert!(enclosing_function_definition(&decl).is_some());
    }
}
