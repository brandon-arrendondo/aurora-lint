//! Shared dataflow semantics for common external function-like macros
//! (utlist, uthash, BSD `<sys/queue.h>`, and a few project iterator macros).
//!
//! Phase 1 of the macro-expansion plan (`docs/design/macro-expansion.md`).
//! sqc parses raw source with no preprocessor, so these macros are opaque: the
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
        // HASH_FIND(hh, head, keyptr, keylen, out)
        "HASH_FIND" => &[Other, Other, Other, Other, Out],
        // HASH_FIND_STR / _INT / _PTR(head, key, out)
        "HASH_FIND_STR" | "HASH_FIND_INT" | "HASH_FIND_PTR" => &[Other, Other, Out],

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
    let roles = match macro_arg_roles(&func_name) {
        Some(r) => r,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for (pos, arg) in positional_args(call).into_iter().enumerate() {
        let role = roles.get(pos).copied().unwrap_or(ArgRole::Other);
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
    let roles = match macro_arg_roles(func_name) {
        Some(r) => r,
        None => return false,
    };
    let target = ident.id();
    for (pos, arg) in positional_args(&call).into_iter().enumerate() {
        if arg.id() == target {
            let role = roles.get(pos).copied().unwrap_or(ArgRole::Other);
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
