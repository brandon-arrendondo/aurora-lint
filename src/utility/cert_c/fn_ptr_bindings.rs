// File-scope function-pointer bindings: which functions a callable variable
// is made to point at anywhere in one translation unit.

use crate::utility::cert_c::ast_utils::{
    file_scope_descendants_of_kinds, get_identifier_from_declarator, get_node_text,
    resolve_identifier_binding, IdentifierBinding,
};
use crate::utility::cert_c::declarator_utils::is_pointer_declarator;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

/// Every file-scope variable declared as a function pointer, mapped to the
/// functions it is bound to anywhere in this translation unit -- by its own
/// initializer and by any later assignment, in source order and without
/// duplicates.
///
/// A name declared as a file-scope function pointer is always present, with
/// an empty list when nothing in the file binds it. That is the answer to
/// "is this callable a function pointer at all", which a caller needs
/// before it can say anything about a call through it.
///
/// **Every binding, not the last one.** A pointer bound in two arms of an
/// `if` is two possible callees on two paths (ADR-0010: arms are
/// alternatives), and lua's `lua.c` is the shape -- `l_getenv = &no_getenv`
/// under `-E`, `l_getenv = &getenv` otherwise. A collector that keeps only
/// the last write answers for one path and silently drops the other; the
/// caller is the one that knows whether its question is MAY (any binding
/// qualifies) or MUST (all of them do).
///
/// Two narrower collectors already exist and neither answers this:
/// `lang_parsing_substrate::calls`'s private `collect_fn_ptr_aliases` and
/// `analyze::function_summary`'s `collect_clearing_names` both record a
/// binding only when the DECLARATION carries an initializer, so a pointer
/// declared bare at file scope and assigned inside some function -- the lua
/// shape, and the `memset_func` idiom's mutable cousin -- is invisible to
/// both.
pub fn file_scope_function_pointer_bindings(
    root: &Node,
    source: &str,
) -> HashMap<String, Vec<String>> {
    let mut bindings: HashMap<String, Vec<String>> = HashMap::new();

    for decl in file_scope_descendants_of_kinds(*root, &["declaration"]) {
        let mut cursor = decl.walk();
        for child in decl.children_by_field_name("declarator", &mut cursor) {
            let (declarator, value) = if child.kind() == "init_declarator" {
                (
                    child.child_by_field_name("declarator"),
                    child.child_by_field_name("value"),
                )
            } else {
                (Some(child), None)
            };
            let Some(declarator) = declarator else {
                continue;
            };
            let Some(name) = function_pointer_variable_name(&declarator, source) else {
                continue;
            };
            let targets = bindings.entry(name).or_default();
            if let Some(value) = value {
                if let Some(target) = binding_target_name(&value, source) {
                    record(targets, target);
                }
            }
        }
    }

    if bindings.is_empty() {
        return bindings;
    }

    for assign in query::find_descendants_of_kind(*root, "assignment_expression") {
        let Some(left) = assign.child_by_field_name("left") else {
            continue;
        };
        if left.kind() != "identifier" {
            continue;
        }
        let name = get_node_text(&left, source);
        if !bindings.contains_key(name) {
            continue;
        }
        // A local or parameter of the same name shadows the file-scope
        // pointer for the rest of its scope, so assigning to it says
        // nothing about what the global points at (ADR-0006).
        if !matches!(
            resolve_identifier_binding(&left, name, source),
            Some(IdentifierBinding::Global(_))
        ) {
            continue;
        }
        let Some(right) = assign.child_by_field_name("right") else {
            continue;
        };
        let Some(target) = binding_target_name(&right, source) else {
            continue;
        };
        if let Some(targets) = bindings.get_mut(name) {
            record(targets, target);
        }
    }

    bindings
}

/// True when `ident_node`, an occurrence of `name` used as a callee, is the
/// file-scope function pointer `bindings` knows about rather than a local of
/// the same name.
pub fn call_resolves_to_file_scope_pointer(
    ident_node: &Node,
    name: &str,
    source: &str,
    bindings: &HashMap<String, Vec<String>>,
) -> bool {
    bindings.contains_key(name)
        && matches!(
            resolve_identifier_binding(ident_node, name, source),
            Some(IdentifierBinding::Global(_))
        )
}

/// The variable name a declarator introduces when -- and only when -- it
/// shapes a function POINTER.
///
/// `char *(*l_getenv)(const char *)` and `char *decc$getenv(const char *)`
/// have the same outer shape (a `pointer_declarator` for the returned
/// `char *` wrapping a `function_declarator`), and the difference is one
/// level in: a pointer variable names itself behind another `*` inside the
/// callable's own declarator, `(*l_getenv)`, where a prototype names the
/// function directly. Requiring that inner pointer is what keeps a
/// pointer-returning prototype out.
fn function_pointer_variable_name(declarator: &Node, source: &str) -> Option<String> {
    let function_declarator =
        query::find_first_descendant(*declarator, |n| n.kind() == "function_declarator")?;
    let inner = function_declarator.child_by_field_name("declarator")?;
    if !is_pointer_declarator(&inner) {
        return None;
    }
    let name = get_identifier_from_declarator(&inner, source);
    (!name.is_empty()).then_some(name)
}

/// The function a function-pointer binding's right-hand side names, through
/// the spellings that denote a function and nothing else: `f`, `&f`, and
/// either wrapped in parentheses or a cast. A call, a field, an array
/// element or anything else computed yields `None` rather than a guess.
fn binding_target_name(node: &Node, source: &str) -> Option<String> {
    let mut n = *node;
    loop {
        match n.kind() {
            "identifier" => return Some(get_node_text(&n, source).to_string()),
            "parenthesized_expression" => n = n.named_child(0)?,
            "cast_expression" => n = n.child_by_field_name("value")?,
            "pointer_expression" | "unary_expression" => n = n.child_by_field_name("argument")?,
            _ => return None,
        }
    }
}

fn record(targets: &mut Vec<String>, target: String) {
    if !targets.contains(&target) {
        targets.push(target);
    }
}
