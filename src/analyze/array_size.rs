//! Shared AST-based array-declaration size resolution.
//!
//! Originated in ARR00-C (task 234) to replace a text-scan approach for
//! out-of-bounds detection; promoted here (task 504) so other rules with the
//! same "what size was this fixed array declared with" question — currently
//! STR31-C — can reuse it instead of re-implementing their own text/regex
//! scan. See `docs/design/str31c-arr00-migration-scoping.md`.

use crate::analyze::const_eval::{try_evaluate_expr, MacroConstantMap};
use crate::utility::cert_c::ast_utils::find_identifier_in_declarator;
use tree_sitter::Node;

/// Resolve an array's declared element count from its AST declaration.
///
/// Finds the `array_declarator` that declares `var_name` in the nearest block
/// scope enclosing `use_node`, then computes its size as
/// `max(evaluated-size-expression, initializer-element-count)`.
///
/// Returns `None` when the bound cannot be determined safely:
///   - the variable has no array declaration in scope,
///   - the explicit size expression is a non-constant we cannot evaluate
///     (e.g. a runtime expression or unknown macro), or
///   - a designated initializer is present without an evaluable explicit size.
///
/// Returning `None` suppresses the out-of-bounds check — the conservative,
/// false-positive-avoiding choice when the true bound is unknown.
pub fn resolve_declared_array_size(
    use_node: &Node,
    var_name: &str,
    source: &str,
    macros: &MacroConstantMap,
) -> Option<usize> {
    let arr_decl = find_array_declarator_in_scope(use_node, var_name, source)?;

    // Evaluate the explicit dimension expression, if any.
    let declared = match arr_decl.child_by_field_name("size") {
        Some(size_expr) => match try_evaluate_expr(&size_expr, source, macros) {
            Some(v) if v > 0 => Some(v as usize),
            // Size expression present but not a positive constant we can
            // evaluate -> bound unknown, do not flag.
            _ => return None,
        },
        // No explicit size (`arr[] = {...}`); rely on the initializer count.
        None => None,
    };

    // Count top-level initializer elements, if the declarator is initialized.
    let init_count = arr_decl
        .parent()
        .filter(|p| p.kind() == "init_declarator")
        .and_then(|p| p.child_by_field_name("value"))
        .filter(|v| v.kind() == "initializer_list")
        .and_then(|v| count_initializer_elements(&v));

    match (declared, init_count) {
        (Some(d), Some(c)) => Some(d.max(c)),
        (Some(d), None) => Some(d),
        (None, Some(c)) => Some(c),
        (None, None) => None,
    }
}

/// Find the `array_declarator` that declares `var_name` and is visible at
/// `use_node`, honoring C block scoping: walk enclosing scopes innermost-first
/// so a block-local `tmp[4]` shadows a `tmp[3]` declared in a sibling block.
fn find_array_declarator_in_scope<'a>(
    use_node: &Node<'a>,
    var_name: &str,
    source: &str,
) -> Option<Node<'a>> {
    let before = use_node.start_byte();
    let mut scope = use_node.parent();
    while let Some(s) = scope {
        if let Some(found) = scan_block_declarators(&s, var_name, source, before) {
            return Some(found);
        }
        scope = s.parent();
    }
    None
}

/// Search one scope for an `array_declarator` of `var_name` declared textually
/// before byte offset `before`, without crossing into nested block scopes
/// (their declarations are not visible here).
fn scan_block_declarators<'a>(
    scope: &Node<'a>,
    var_name: &str,
    source: &str,
    before: usize,
) -> Option<Node<'a>> {
    for i in 0..scope.child_count() {
        if let Some(child) = scope.child(i) {
            // A nested block / function body is a separate scope — skip it.
            if matches!(child.kind(), "compound_statement" | "function_definition") {
                continue;
            }
            if child.kind() == "array_declarator"
                && child.start_byte() < before
                && find_identifier_in_declarator(&child, source).as_deref() == Some(var_name)
            {
                return Some(child);
            }
            if let Some(found) = scan_block_declarators(&child, var_name, source, before) {
                return Some(found);
            }
        }
    }
    None
}

/// Count top-level elements in an `initializer_list`.
///
/// Returns `None` if the list uses designated initializers (e.g. `[3] = x`),
/// where the element count does not bound the array size.
fn count_initializer_elements(list: &Node) -> Option<usize> {
    let mut count = 0;
    for i in 0..list.child_count() {
        if let Some(child) = list.child(i) {
            match child.kind() {
                "{" | "}" | "," | "comment" => {}
                // Designated initializer (`[idx] = v` or `.field = v`): the
                // element count does not bound the array size -> give up.
                "initializer_pair" => return None,
                _ => count += 1,
            }
        }
    }
    if count > 0 {
        Some(count)
    } else {
        None
    }
}
