//! Shared dataflow semantics for common external function-like macros
//! (utlist, uthash, BSD `<sys/queue.h>`, and a few project iterator macros).
//!
//! Phase 1 of the macro-expansion plan (`docs/design/macro-expansion.md`).
//! aurora-lint parses raw source with no preprocessor, so these macros are opaque: the
//! parser sees `MACRO(head, el, tmp)` as a `call_expression` and (for the
//! block-bearing iterator macros) the loop body as a *detached following
//! sibling* `compound_statement`. The macro actually initializes its
//! iterator/temp/out arguments and, for loop macros, guarantees the iterator is
//! non-null inside the body. Dataflow analyses consult this registry instead of
//! re-deriving that per rule.
//!
//! This is a *positional* registry: each entry lists the role of each
//! comma-separated argument by position. It is the single source of truth that
//! replaces the old `init_state::FOR_EACH_MACROS` first-arg-only heuristic
//! (which was wrong for utlist/uthash, where the head is the input at arg 0 and
//! the iterator/temp/out vars are later args).

use tree_sitter::Node;

/// Role of a positional macro argument w.r.t. dataflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgRole {
    /// Loop iterator variable: initialized by the macro AND guaranteed non-null
    /// *inside the macro's body block* (the expanded loop condition guards it).
    Iterator,
    /// Temp / "next" variable written by the macro (e.g. the `_SAFE` tmp). It is
    /// initialized but may legitimately be null (e.g. `el->next` at list end).
    Temp,
    /// Output variable of a find/search macro: initialized, may be null
    /// (the caller is expected to null-check it).
    Out,
    /// Any other argument (head/list/field/key/length/etc.) — not modeled.
    Other,
}

/// Look up the positional argument roles for a known iterator/find/output macro.
/// Roles are indexed by comma-separated argument position (0-based). Returns
/// `None` if the macro is not in the registry. A position past the end of the
/// returned slice is treated as [`ArgRole::Other`].
pub fn macro_arg_roles(name: &str) -> Option<&'static [ArgRole]> {
    use ArgRole::*;
    Some(match name {
        // ---- utlist iterator macros: (head, el [, tmp ...]) ----
        "LL_FOREACH" | "DL_FOREACH" | "CDL_FOREACH" | "LL_FOREACH2" | "DL_FOREACH2"
        | "CDL_FOREACH2" => &[Other, Iterator],
        "LL_FOREACH_SAFE" | "DL_FOREACH_SAFE" | "LL_FOREACH_SAFE2" | "DL_FOREACH_SAFE2" => {
            &[Other, Iterator, Temp]
        }
        "CDL_FOREACH_SAFE" | "CDL_FOREACH_SAFE2" => &[Other, Iterator, Temp, Temp],
        // utlist search macros: (head, out, ...) -> out at arg 1
        "LL_SEARCH_SCALAR" | "DL_SEARCH_SCALAR" | "CDL_SEARCH_SCALAR" | "LL_SEARCH"
        | "DL_SEARCH" | "CDL_SEARCH" | "LL_SEARCH_SCALAR2" | "DL_SEARCH_SCALAR2"
        | "CDL_SEARCH_SCALAR2" => &[Other, Out],

        // ---- uthash ----
        // HASH_ITER(hh, head, el, tmp)
        "HASH_ITER" => &[Other, Other, Iterator, Temp],
        // NB: the HASH_FIND* / HASH_REPLACE* family (output = last arg) is handled
        // by prefix in `is_hash_find_family`, not enumerated here.

        // ---- BSD <sys/queue.h>: (var, head, field [, tvar]) -> var at arg 0 ----
        "TAILQ_FOREACH" | "LIST_FOREACH" | "SLIST_FOREACH" | "STAILQ_FOREACH"
        | "SIMPLEQ_FOREACH" | "CIRCLEQ_FOREACH" => &[Iterator],
        "TAILQ_FOREACH_SAFE"
        | "LIST_FOREACH_SAFE"
        | "SLIST_FOREACH_SAFE"
        | "STAILQ_FOREACH_SAFE" => &[Iterator, Other, Other, Temp],
        // RB_FOREACH(var, name, head)
        "RB_FOREACH" => &[Iterator],

        // ---- project iterator macros (preserved from the old FOR_EACH_MACROS,
        //      iterator at arg 0) ----
        "dl_list_for_each"
        | "dl_list_for_each_safe"
        | "dl_list_for_each_reverse"
        | "for_each_link" => &[Iterator],

        _ => return None,
    })
}

/// True for the uthash `HASH_FIND*` / `HASH_REPLACE*` family, whose output
/// (the found / replaced item) is always the LAST argument. Matched by prefix
/// so new variants (e.g. `HASH_FIND_BYHASHVALUE`, `HASH_REPLACE_INORDER`) are
/// covered without enumeration.
pub fn is_hash_find_family(name: &str) -> bool {
    name.starts_with("HASH_FIND") || name.starts_with("HASH_REPLACE")
}

/// True if `name` is any registered macro (explicit iterator table or the
/// find/replace family).
pub fn is_registered(name: &str) -> bool {
    macro_arg_roles(name).is_some() || is_hash_find_family(name)
}

/// Known utlist/uthash "unlink from container" macros whose name
/// coincidentally matches deallocator-name heuristics (an `_delete` suffix,
/// e.g. `HASH_DELETE`, `DL_DELETE`) but which only remove an element from a
/// hash table or linked list — they never call `free()` on their argument.
/// Misclassifying one as a deallocator causes a spurious double-free finding
/// when the real `free()`/`mosquitto_FREE()` call immediately follows, as in
/// the common `HASH_DELETE(hh, tbl, x); free(x);` idiom (task 426).
pub fn is_container_unlink_macro(name: &str) -> bool {
    matches!(
        name,
        "HASH_DELETE"
            | "HASH_DELETE_BYHASHVALUE"
            | "DL_DELETE"
            | "DL_DELETE2"
            | "LL_DELETE"
            | "LL_DELETE2"
            | "CDL_DELETE"
            | "CDL_DELETE2"
    )
}

/// Role of the argument at positional index `pos` for macro `name`, given a
/// call with `nargs` positional arguments. Combines the explicit positional
/// table with the find-family "last arg is Out" rule.
fn arg_role_at(name: &str, pos: usize, nargs: usize) -> ArgRole {
    if let Some(roles) = macro_arg_roles(name) {
        return roles.get(pos).copied().unwrap_or(ArgRole::Other);
    }
    if is_hash_find_family(name) && nargs > 0 && pos == nargs - 1 {
        return ArgRole::Out;
    }
    ArgRole::Other
}

/// Collect the comma-separated argument nodes of a `call_expression`'s
/// `argument_list`, in order, skipping punctuation tokens. Position in the
/// returned vec equals the positional index used by [`macro_arg_roles`].
pub fn positional_args<'a>(call: &Node<'a>) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    if let Some(args) = call.child_by_field_name("arguments") {
        for i in 0..args.child_count() {
            if let Some(arg) = args.child(i) {
                if matches!(arg.kind(), "(" | ")" | ",") {
                    continue;
                }
                out.push(arg);
            }
        }
    }
    out
}

/// For a `call_expression` that is a registered macro, yield `(var_name, role)`
/// for each positional argument that is a bare identifier with a modeled role
/// (Iterator / Temp / Out). Used by the init/null transfer functions.
pub fn output_var_args(call: &Node, source: &str) -> Vec<(String, ArgRole)> {
    let func_name = match call.child_by_field_name("function") {
        Some(f) => f.utf8_text(source.as_bytes()).unwrap_or("").to_string(),
        None => return Vec::new(),
    };
    if !is_registered(&func_name) {
        return Vec::new();
    }
    let args = positional_args(call);
    let nargs = args.len();
    let mut out = Vec::new();
    for (pos, arg) in args.into_iter().enumerate() {
        let role = arg_role_at(&func_name, pos, nargs);
        if matches!(role, ArgRole::Iterator | ArgRole::Temp | ArgRole::Out)
            && arg.kind() == "identifier"
        {
            let name = arg.utf8_text(source.as_bytes()).unwrap_or("").to_string();
            if !name.is_empty() {
                out.push((name, role));
            }
        }
    }
    out
}

/// True if `ident` is a bare-identifier argument occupying a modeled
/// (Iterator/Temp/Out) position of a registered macro invocation — i.e. the
/// macro *writes* this argument, so reading it there is not a use of an
/// uninitialized value. Used by the EXP33 read-checker to avoid flagging the
/// macro's own output arguments.
pub fn is_macro_output_arg(ident: &Node, source: &str) -> bool {
    if ident.kind() != "identifier" {
        return false;
    }
    // ident -> argument_list -> call_expression
    let arg_list = match ident.parent() {
        Some(p) if p.kind() == "argument_list" => p,
        _ => return false,
    };
    let call = match arg_list.parent() {
        Some(c) if c.kind() == "call_expression" => c,
        _ => return false,
    };
    let func_name = match call.child_by_field_name("function") {
        Some(f) => f.utf8_text(source.as_bytes()).unwrap_or(""),
        None => return false,
    };
    if !is_registered(func_name) {
        return false;
    }
    let args = positional_args(&call);
    let nargs = args.len();
    let target = ident.id();
    for (pos, arg) in args.into_iter().enumerate() {
        if arg.id() == target {
            let role = arg_role_at(func_name, pos, nargs);
            return matches!(role, ArgRole::Iterator | ArgRole::Temp | ArgRole::Out);
        }
    }
    false
}

/// True if `node` lies within the *body block* of a registered iterator macro
/// whose [`ArgRole::Iterator`] argument is `var` — i.e. the deref of `var` is
/// guarded non-null by the (invisible) loop condition. The body block is the
/// `compound_statement` that immediately follows the macro `call_expression`
/// statement as a sibling (see `docs/design/macro-expansion.md` §8a).
pub fn is_in_iterator_macro_body(node: &Node, source: &str, var: &str) -> bool {
    // Walk up to find an enclosing compound_statement whose immediately-preceding
    // sibling is a registered iterator-macro call naming `var` as its iterator.
    let mut cur = *node;
    while let Some(parent) = cur.parent() {
        if cur.kind() == "compound_statement" {
            if let Some(prev) = cur.prev_named_sibling() {
                if iterator_macro_call_for(&prev, source, var) {
                    return true;
                }
            }
        }
        cur = parent;
    }
    false
}

/// True if `stmt` is (or wraps) a registered iterator-macro `call_expression`
/// whose iterator argument is `var`.
fn iterator_macro_call_for(stmt: &Node, source: &str, var: &str) -> bool {
    // The macro call appears as an expression_statement -> call_expression
    // (with a MISSING ";"), or occasionally as a bare call_expression.
    let call = if stmt.kind() == "call_expression" {
        *stmt
    } else if stmt.kind() == "expression_statement" {
        match stmt.child(0) {
            Some(c) if c.kind() == "call_expression" => c,
            _ => return false,
        }
    } else {
        return false;
    };
    let func_name = match call.child_by_field_name("function") {
        Some(f) => f.utf8_text(source.as_bytes()).unwrap_or(""),
        None => return false,
    };
    let roles = match macro_arg_roles(func_name) {
        Some(r) => r,
        None => return false,
    };
    for (pos, arg) in positional_args(&call).into_iter().enumerate() {
        if roles.get(pos).copied() == Some(ArgRole::Iterator)
            && arg.kind() == "identifier"
            && arg.utf8_text(source.as_bytes()).unwrap_or("") == var
        {
            return true;
        }
    }
    false
}
