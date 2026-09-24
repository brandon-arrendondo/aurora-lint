// Common AST utilities for CERT C rules
// This module provides reusable functions for navigating and extracting information from the C AST

use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

// ============================================================================
// Node Text Extraction
// ============================================================================

/// Extract the text content of a node from the source code
pub fn get_node_text<'a>(node: &Node, source: &'a str) -> &'a str {
    query::node_text(*node, source.as_bytes())
}

/// Heuristic: does this call's name look like a custom deallocator
/// (destroy_*, free_*, delete_*, cleanup_*, release_*, close_*, or the
/// matching suffix forms)? Shared between MEM31-C's own custom-deallocator
/// handling and the prescan field-frees collector (`frees_param_fields`),
/// so a macro-wrapped free like `#define mosquitto_FREE(A) free(A)` is
/// recognized consistently in both places (an earlier fix: MEM31-C ownership model —
/// aurora-lint has no preprocessor, so such wrapper calls are otherwise invisible).
pub fn is_deallocation_call_name(func_name: &str) -> bool {
    if crate::analyze::macro_semantics::is_container_unlink_macro(func_name) {
        return false;
    }
    let lower_name = func_name.to_lowercase();
    lower_name.starts_with("destroy_")
        || lower_name.starts_with("free_")
        || lower_name.starts_with("delete_")
        || lower_name.starts_with("cleanup_")
        || lower_name.starts_with("release_")
        || lower_name.starts_with("close_")
        || lower_name.ends_with("_destroy")
        || lower_name.ends_with("_free")
        || lower_name.ends_with("_delete")
        || lower_name.ends_with("_cleanup")
        || lower_name.ends_with("_release")
        || lower_name.ends_with("_close")
}

/// Extract the text content of a node as an owned String
pub fn get_node_text_owned(node: &Node, source: &str) -> String {
    query::node_text(*node, source.as_bytes()).to_string()
}

/// Extract a node's text with comment, string-literal, and char-literal spans
/// blanked out (replaced with spaces, preserving byte offsets/length).
///
/// For rules whose heuristics are too intricate to safely re-derive as pure
/// AST structural checks, this lets an existing text-substring heuristic run
/// against sanitized text instead — so a `.contains("UINT_MAX")` or similar
/// pattern can no longer be spoofed by a comment or string literal elsewhere
/// in the scanned span (a real false-negative risk: silent suppression of a
/// genuine violation, which is the worse failure direction for a security tool).
pub fn get_sanitized_node_text(node: &Node, source: &str) -> String {
    let start = node.start_byte();
    let end = node.end_byte();
    let mut bytes = source.as_bytes()[start..end].to_vec();
    for lit in
        query::find_descendants_of_kinds(*node, &["comment", "string_literal", "char_literal"])
    {
        let lit_start = lit.start_byte().max(start);
        let lit_end = lit.end_byte().min(end);
        if lit_start < lit_end {
            // Blank every byte except embedded newlines, so a multi-line
            // comment/string doesn't collapse onto one line — callers that
            // scan sanitized text line-by-line (`.lines()`) rely on the
            // original line structure being preserved.
            for b in &mut bytes[(lit_start - start)..(lit_end - start)] {
                if *b != b'\n' {
                    *b = b' ';
                }
            }
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

// ============================================================================
// AST Navigation
// ============================================================================

/// A per-file cache of every AST node's parent, so an ancestor walk pays
/// O(1) per step instead of O(depth).
///
/// `tree_sitter::Node::parent()` is not a pointer hop -- it recovers a parent
/// by descending from the tree root, so one call costs O(depth). A rule that
/// walks up from a node therefore pays O(depth^2), and running that once per
/// descendant of a file whose node count grows with its nesting depth is
/// cubic. On the 2,000-level `if`-nesting fixture that cost ~24 s total
/// across the whole rule set (this repo); STR34-C alone spent 2.9 s
/// there re-descending from the root once per identifier.
///
/// Build one map per file with `ParentMap::new(root)` (a single pre-order
/// walk, O(n)), then hand `&ParentMap` to the ancestor helpers below. Any
/// rule that walks ancestors more than a bounded few levels should use this
/// -- pattern (3) in `docs/design/internal-capability-catalog.md`, alongside
/// prune-on-the-way-down and carry-a-stack.
pub struct ParentMap<'a> {
    parents: std::collections::HashMap<usize, Node<'a>>,
}

impl<'a> ParentMap<'a> {
    /// Build a parent map for every node in `root`'s subtree with a single
    /// pre-order walk (O(n) nodes, O(1) per step).
    pub fn new(root: Node<'a>) -> Self {
        let mut parents = std::collections::HashMap::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                parents.insert(child.id(), node);
                stack.push(child);
            }
        }
        Self { parents }
    }

    /// The direct parent of `node`, or `None` if `node` is the map's root.
    pub fn parent_of(&self, node: Node<'a>) -> Option<Node<'a>> {
        self.parents.get(&node.id()).copied()
    }

    /// The nearest strict ancestor of `node` satisfying `pred`, or `None`.
    pub fn find_ancestor(
        &self,
        node: Node<'a>,
        mut pred: impl FnMut(Node<'a>) -> bool,
    ) -> Option<Node<'a>> {
        let mut cur = self.parent_of(node);
        while let Some(n) = cur {
            if pred(n) {
                return Some(n);
            }
            cur = self.parent_of(n);
        }
        None
    }
}

/// Find the containing function definition for a given node
/// Returns the function_definition node that contains the given node
pub fn find_containing_function<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    if node.kind() == "function_definition" {
        return Some(*node);
    }
    query::nearest_ancestor_of_kind(*node, "function_definition")
}

/// Every descendant of `root` matching one of `kinds` that lies **outside**
/// any function definition, found by pruning at `function_definition` on the
/// way down.
///
/// Use this instead of collecting all descendants and rejecting the ones
/// [`find_containing_function`] answers for. `Node::parent()` is not a
/// pointer hop: tree-sitter recovers a parent by descending from the tree
/// root, so it costs O(depth). An ancestor query per candidate therefore
/// costs O(depth²), and running one over a whole file whose node count grows
/// with its nesting depth makes the pass cubic — 800 nested `if`s took
/// CON40-C 23 s before this replaced two such filters (this repo).
/// Pruning is O(n) and needs no ancestor query at all.
pub fn file_scope_descendants_of_kinds<'a>(root: Node<'a>, kinds: &[&str]) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_definition" {
            continue;
        }
        if kinds.contains(&node.kind()) {
            out.push(node);
        }
        let mut cursor = node.walk();
        let children: Vec<Node<'a>> = node.children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    out
}

/// Walk up from `ident_node` through enclosing scopes — `compound_statement`
/// blocks and `for_statement` init clauses — to find the nearest
/// `declaration` that binds `name`, preferring the latest (highest byte
/// offset) such declaration before `ident_node`'s own position within each
/// scope. Correctly disambiguates shadowed re-declarations of the same name
/// in sibling or nested blocks — unlike a whole-function text/regex scan,
/// which cannot tell two different declarations of the same identifier
/// apart.
///
/// `for (int i = 0; i < n; i++) { ... }` declares `i` as a direct child of
/// the `for_statement` itself, not of any `compound_statement` — its scope
/// is the whole for-statement (condition, update, and body). A search that
/// only scanned `compound_statement` children would never find it, making
/// every read of a for-loop variable (in the condition, the update, or the
/// body) fail to resolve back to its own declaration.
///
/// A scope's own declaration search is preprocessor-transparent: `#ifdef
/// X ... #endif` is textual inclusion, not a new C scope, so `int color;`
/// written inside one has the same enclosing-block scope as if it were
/// written directly — a read anywhere else in that same block (inside a
/// different `#ifdef`/`#else` branch, or after the `#endif` entirely) must
/// still resolve back to it. Scanning only literal `declaration`-kind
/// direct children would miss any declaration nested one or more
/// `preproc_if`/`preproc_ifdef`/`preproc_elif`/`preproc_else` levels down.
///
/// Stops at the function body (does not resolve to a parameter — callers
/// needing that should also check `is_function_parameter` separately).
pub fn find_enclosing_declaration_for_identifier<'a>(
    ident_node: &Node<'a>,
    name: &str,
    source: &str,
) -> Option<Node<'a>> {
    let mut scopes = Vec::new();
    let mut search_from = *ident_node;
    while let Some(scope) = query::find_ancestor(search_from, |n| is_declaration_scope(&n)) {
        scopes.push(scope);
        search_from = scope;
    }
    find_declaration_in_scope_chain(&scopes, ident_node.start_byte(), name, source)
}

/// True if `node` opens one of the scopes
/// [`find_enclosing_declaration_for_identifier`] searches.
pub fn is_declaration_scope(node: &Node) -> bool {
    matches!(node.kind(), "compound_statement" | "for_statement")
}

/// The body of [`find_enclosing_declaration_for_identifier`], over a scope
/// chain the caller already has: `scopes` innermost-first, `ident_start` the
/// identifier's start byte.
///
/// A caller already descending the tree can keep that chain on a stack for
/// free. Rediscovering it per identifier cannot: `Node::parent()` recovers a
/// parent by descending from the tree root, so it costs O(depth), one
/// resolution costs O(depth²), and resolving every read in a file whose node
/// count grows with its nesting depth is cubic -- 2,000 nested `if`s took
/// MSC13-C 93 s (this repo).
pub fn find_declaration_in_scope_chain<'a>(
    scopes: &[Node<'a>],
    ident_start: usize,
    name: &str,
    source: &str,
) -> Option<Node<'a>> {
    for scope in scopes {
        let mut declarations = Vec::new();
        collect_declarations_transparent_to_preproc(scope, &mut declarations);
        let best = declarations
            .into_iter()
            .filter(|child| {
                child.start_byte() < ident_start && declaration_binds_name(child, name, source)
            })
            .max_by_key(|child| child.start_byte());
        if best.is_some() {
            return best;
        }
    }
    None
}

/// Collect every `declaration` directly inside `scope`, transparently
/// descending into any nested `#if`/`#ifdef`/`#elif`/`#else` branch (any
/// depth) — see [`find_enclosing_declaration_for_identifier`] for why —
/// and into `case`/`default` labels, which are not scopes either.
///
/// A `case` label with no braces around its body does not open a block:
/// `switch (x) { case 1: int y = f(); g(y); }` declares `y` in the
/// switch's own compound_statement, exactly as if the label were not
/// there. tree-sitter-c nests those statements under a `case_statement`
/// node all the same, so scanning only the compound_statement's literal
/// children finds no declaration and every read of `y` fails to resolve
/// back to it. A `case` whose body IS braced is a different matter: the
/// `compound_statement` under the label is a real scope and is left to
/// the caller's outward walk, which is why the recursion below descends
/// through `case_statement` but never through a block.
fn collect_declarations_transparent_to_preproc<'a>(scope: &Node<'a>, out: &mut Vec<Node<'a>>) {
    let condition_id = scope.child_by_field_name("condition").map(|n| n.id());
    let name_id = scope.child_by_field_name("name").map(|n| n.id());
    for i in 0..scope.child_count() {
        let Some(child) = scope.child(i) else {
            continue;
        };
        if Some(child.id()) == condition_id || Some(child.id()) == name_id {
            continue;
        }
        match child.kind() {
            "declaration" => out.push(child),
            "preproc_if" | "preproc_ifdef" | "preproc_elif" | "preproc_else" | "case_statement" => {
                collect_declarations_transparent_to_preproc(&child, out);
            }
            _ => {}
        }
    }
}

/// True if a `declaration` node binds `name` via a direct declarator (`T
/// name;`) or an `init_declarator` (`T name = value;`), including
/// comma-separated multi-declarator declarations.
fn declaration_binds_name(decl_node: &Node, name: &str, source: &str) -> bool {
    declaration_declarator_for(decl_node, name, source).is_some()
}

/// The specific declarator sub-node within a (possibly multi-declarator)
/// `declaration` -- or a `parameter_declaration`, which has the same child
/// shape -- that binds `name`, so its own node kind can be inspected: `int
/// a, *b;` must not report `a` as a pointer just because `b` is one in the
/// same declaration. An `init_declarator` is unwrapped to the declarator it
/// carries. `None` when no declarator in the node binds `name`.
pub fn declaration_declarator_for<'a>(
    decl_node: &Node<'a>,
    name: &str,
    source: &str,
) -> Option<Node<'a>> {
    for i in 0..decl_node.child_count() {
        let child = decl_node.child(i)?;
        let declarator = match child.kind() {
            "init_declarator" => child.child_by_field_name("declarator").unwrap_or(child),
            "identifier" | "pointer_declarator" | "array_declarator" | "function_declarator" => {
                child
            }
            _ => continue,
        };
        if get_identifier_from_declarator(&declarator, source) == name {
            return Some(declarator);
        }
    }
    None
}

/// The `parameter_declaration` node of `function_node` that binds `name`.
/// Node-level counterpart of the `(name, type text)` pairs
/// [`get_function_parameters`] returns, for callers that need the
/// declarator's own kind rather than a textual type (a `*` in the text
/// cannot say whether it belongs to this name or to a sibling).
pub fn find_parameter_declaration<'a>(
    function_node: &Node<'a>,
    name: &str,
    source: &str,
) -> Option<Node<'a>> {
    let declarator = find_function_declarator(function_node)?;
    let params = declarator.child_by_field_name("parameters")?;
    (0..params.child_count())
        .filter_map(|i| params.child(i))
        .filter(|p| p.kind() == "parameter_declaration")
        .find(|p| declaration_declarator_for(p, name, source).is_some())
}

/// Resolve `ident_node` (an occurrence of `name`) to the node that declares
/// it AND the declarator within that node which binds this name:
/// `(declaration | parameter_declaration, declarator)`. Same three-way
/// fallback as [`resolve_identifier_binding`] (nearest enclosing local
/// declaration, else the containing function's parameter, else a file-scope
/// global), but hands back nodes for the parameter case too, so a caller
/// classifying the declared type can read the specifiers and the declarator
/// kind by one code path regardless of where the name was bound. Reach for
/// this over [`resolve_identifier_binding`] when the question is "what TYPE
/// is this name declared with here" rather than "where is it bound".
pub fn resolve_identifier_declarator<'a>(
    ident_node: &Node<'a>,
    name: &str,
    source: &str,
) -> Option<(Node<'a>, Node<'a>)> {
    let decl = match resolve_identifier_binding(ident_node, name, source)? {
        IdentifierBinding::Local(decl) | IdentifierBinding::Global(decl) => decl,
        IdentifierBinding::Parameter(_) => {
            let func = find_containing_function(ident_node)?;
            find_parameter_declaration(&func, name, source)?
        }
    };
    let declarator = declaration_declarator_for(&decl, name, source)?;
    Some((decl, declarator))
}

/// The declared type of the variable `ident_node` (an occurrence of `name`)
/// refers to, spelled the way the integer-hazard rules' type maps spell it:
/// the declaration's `type` field verbatim (`size_t`, `unsigned long`,
/// `struct foo`, a typedef alias), with ` *` appended when the declarator is
/// a pointer or an array -- an array name used as an operand decays to a
/// pointer. Storage classes and qualifiers are not part of the `type` field
/// and so never appear.
///
/// This is [`resolve_identifier_declarator`] asked the type question, and it
/// exists because a file-wide `{name -> type}` map answers it wrong whenever
/// two functions declare the same name differently: hostap's wpa_auth.c has
/// `size_t wpa_ie_len` in one function and `int wpa_ie_len` in another, and
/// the map handed the second to the first (ADR-0006). `None` when
/// the occurrence does not resolve to a declaration in this file.
pub fn resolve_identifier_declared_type(
    ident_node: &Node,
    name: &str,
    source: &str,
) -> Option<String> {
    let (decl, declarator) = resolve_identifier_declarator(ident_node, name, source)?;
    let base = get_node_text(&decl.child_by_field_name("type")?, source)
        .trim()
        .to_string();
    if base.is_empty() {
        return None;
    }
    let mut d = declarator;
    let mut pointer_like = false;
    loop {
        match d.kind() {
            "pointer_declarator" | "array_declarator" => pointer_like = true,
            // `T (*fp)(...)` / `T *f(...)`: a function pointer or a function,
            // neither an integer operand this spelling can describe.
            "function_declarator" => return None,
            "parenthesized_declarator" => {}
            _ => break,
        }
        match d.child_by_field_name("declarator") {
            Some(inner) => d = inner,
            None => break,
        }
    }
    Some(if pointer_like {
        format!("{} *", base)
    } else {
        base
    })
}

/// Fallback for file-scope (global) declarations, which
/// `find_enclosing_declaration_for_identifier` intentionally does not
/// resolve to (it only walks enclosing `compound_statement` blocks).
/// Restricted to direct children of the translation unit so it can't cross
/// into an unrelated function body.
///
/// This generalizes a scan that MSC05-C, MSC15-C, and CON34-C each
/// hand-rolled independently (an earlier fix item #3) as a type- or
/// qualifier-filtered variant of the same walk.
pub fn find_global_declaration_for_identifier<'a>(
    ident_node: &Node<'a>,
    name: &str,
    source: &str,
) -> Option<Node<'a>> {
    let mut top = *ident_node;
    while let Some(p) = top.parent() {
        top = p;
    }
    (0..top.child_count())
        .filter_map(|i| top.child(i))
        .find(|decl| decl.kind() == "declaration" && declaration_binds_name(decl, name, source))
}

/// Where an identifier use resolves to its binding declaration/parameter.
pub enum IdentifierBinding<'a> {
    /// Bound by a local (block-scope) declaration.
    Local(Node<'a>),
    /// Bound by a function parameter; carries the parameter's type text
    /// since a parameter has no `declaration` node of its own to point at.
    Parameter(String),
    /// Bound by a file-scope (translation-unit level) declaration.
    Global(Node<'a>),
}

/// Resolve `ident_node` (an occurrence of `name`) to wherever it's bound:
/// the nearest enclosing local declaration, else the containing function's
/// parameter list, else a file-scope global declaration. Chains
/// [`find_enclosing_declaration_for_identifier`], [`get_function_parameters`],
/// and [`find_global_declaration_for_identifier`] in that order so callers
/// don't each hand-roll the same 3-way fallback (an earlier fix item #3 -- MSC05-C,
/// MSC15-C, FIO34-C, ENV34-C, INT34-C, and CON34-C all did this
/// independently).
pub fn resolve_identifier_binding<'a>(
    ident_node: &Node<'a>,
    name: &str,
    source: &str,
) -> Option<IdentifierBinding<'a>> {
    if let Some(decl) = find_enclosing_declaration_for_identifier(ident_node, name, source) {
        return Some(IdentifierBinding::Local(decl));
    }
    if let Some(func) = find_containing_function(ident_node) {
        if let Some(params) = get_function_parameters(&func, source) {
            if let Some((_, ptype)) = params.iter().find(|(n, _)| n == name) {
                return Some(IdentifierBinding::Parameter(ptype.clone()));
            }
        }
    }
    find_global_declaration_for_identifier(ident_node, name, source).map(IdentifierBinding::Global)
}

/// Extract the type text (tokens before the declarator) of a `declaration`
/// node, e.g. `time_t x;` -> `"time_t"`, `static unsigned int x;` ->
/// `"static unsigned int"`. Public because this exact scan was independently
/// hand-rolled in ARR39-C, MSC15-C, and FIO34-C before being
/// consolidated here.
pub fn declaration_type_text(decl: &Node, source: &str) -> String {
    (0..decl.child_count())
        .filter_map(|i| decl.child(i))
        .take_while(|c| {
            !matches!(
                c.kind(),
                "identifier" | "init_declarator" | "pointer_declarator" | "array_declarator"
            )
        })
        .map(|c| get_node_text(&c, source))
        .collect::<Vec<_>>()
        .join(" ")
}

/// True if a `declaration` node carries the given `type_qualifier` (e.g.
/// `"const"`, `"volatile"`) as a direct child. Only looks at the
/// declaration's own qualifiers, not a specific declarator's — matches the
/// pattern already used by callers checking e.g. `const char *ptr;`.
pub fn declaration_has_qualifier(decl: &Node, qualifier: &str, source: &str) -> bool {
    (0..decl.child_count()).any(|i| {
        decl.child(i)
            .is_some_and(|c| c.kind() == "type_qualifier" && get_node_text(&c, source) == qualifier)
    })
}

/// True if a `declaration` node carries the given `storage_class_specifier`
/// (e.g. `"static"`, `"extern"`) as a direct child.
pub fn declaration_has_storage_class(decl: &Node, storage_class: &str, source: &str) -> bool {
    (0..decl.child_count()).any(|i| {
        decl.child(i).is_some_and(|c| {
            c.kind() == "storage_class_specifier" && get_node_text(&c, source) == storage_class
        })
    })
}

/// True if `node` is a `*p`-style dereference. `*p` and `&p` both parse as
/// `pointer_expression` in this grammar, disambiguated only by the
/// `operator` field's text -- conflating them is a real FP source (an
/// earlier MEM33-C fix, MEM30-C's `scope_derefs_var`), so this is the shared
/// primitive rather than each rule re-deriving the field check.
pub fn is_dereference_expression(node: &Node, source: &str) -> bool {
    node.kind() == "pointer_expression"
        && node
            .child_by_field_name("operator")
            .is_some_and(|o| get_node_text(&o, source) == "*")
}

/// True if `node` is a `&p`-style address-of expression. See
/// [`is_dereference_expression`].
pub fn is_address_of_expression(node: &Node, source: &str) -> bool {
    node.kind() == "pointer_expression"
        && node
            .child_by_field_name("operator")
            .is_some_and(|o| get_node_text(&o, source) == "&")
}

/// Convenience wrapper over [`resolve_identifier_binding`] for callers that
/// only need the resolved type text, not the binding site itself.
pub fn resolve_identifier_type(ident_node: &Node, name: &str, source: &str) -> Option<String> {
    match resolve_identifier_binding(ident_node, name, source)? {
        IdentifierBinding::Local(decl) | IdentifierBinding::Global(decl) => {
            Some(declaration_type_text(&decl, source))
        }
        IdentifierBinding::Parameter(ptype) => Some(ptype),
    }
}

/// Check if a node is inside a loop (for, while, or do-while)
///
/// No function-boundary short-circuit: `function_definition`s never nest in
/// C, so walking past one to check outer scopes can't happen in practice —
/// same result as the boundary-stopping version, one predicate instead of two.
pub fn is_inside_loop(node: &Node) -> bool {
    query::find_ancestor(*node, |n| {
        matches!(
            n.kind(),
            "for_statement" | "while_statement" | "do_statement"
        )
    })
    .is_some()
}

/// Check if a node is inside a conditional statement (if, else if, switch)
#[allow(dead_code)]
pub fn is_inside_conditional(node: &Node) -> bool {
    query::find_ancestor(*node, |n| {
        matches!(n.kind(), "if_statement" | "switch_statement")
    })
    .is_some()
}

/// Whether `node` sits inside the CONDITION of a preprocessor conditional —
/// the `A && B` of `#if A && B` or `#elif A && B`.
///
/// Deliberately narrower than "inside a preprocessor conditional". A node in
/// the guarded BODY of an `#if`/`#ifdef` is ordinary runtime code and answers
/// `false`; only the directive's own condition answers `true`. That condition
/// is evaluated by the preprocessor at translation time, so runtime notions —
/// side effects, evaluation order, short-circuit skipping — do not apply to
/// it, and a rule reasoning about them must not descend into it. Walking up
/// to any `preproc_*` ancestor instead (as a rule wanting "is this
/// conditionally compiled" would) answers `true` for the body too, which
/// silently suppresses real findings in every `#ifdef` block in the corpus.
///
/// `#ifdef`/`#ifndef` (`preproc_ifdef`) carry a bare macro `name` rather than
/// an expression, so they hold no node this can be asked about.
pub fn is_in_preproc_condition(node: &Node) -> bool {
    let mut current = *node;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "preproc_if" | "preproc_elif")
            && parent
                .child_by_field_name("condition")
                .is_some_and(|c| c.id() == current.id())
        {
            return true;
        }
        current = parent;
    }
    false
}

/// Whether `node` is a file-scope include guard: `#ifndef NAME` whose first
/// directive is `#define NAME`, with no `#else`/`#elif` arm.
///
/// The idiom guards a header against double inclusion, so the definitions
/// under it are the header's ONLY definitions — never one arm of an
/// alternate-body choice. A predicate that treats every `preproc_ifdef`
/// ancestor as "conditionally compiled" (the shape an earlier fix's gate wanted,
/// for a `#if X ... #else` stub body) makes every function in every guarded
/// header conditional: hostap's `dl_list_add` in `list.h` then earns no
/// `stores_params`, and the intrusive-list linkers built on it lose their
/// borrowed-result reading. Ask this before walking up to a
/// preprocessor ancestor and stop at a guard.
///
/// Deliberately tight: top level of the file (`translation_unit` parent), the
/// `#ifndef` form, and the name re-`#define`d as the first directive under
/// it. A guard-shaped block nested in a function, or one with an `#else`,
/// answers `false` and keeps whatever caution the caller had.
pub fn is_include_guard(node: &Node, source: &str) -> bool {
    if node.kind() != "preproc_ifdef"
        || node.child(0).is_none_or(|d| d.kind() != "#ifndef")
        || node.parent().is_none_or(|p| p.kind() != "translation_unit")
        || node.child_by_field_name("alternative").is_some()
    {
        return false;
    }
    let Some(name) = node.child_by_field_name("name") else {
        return false;
    };
    let name = get_node_text(&name, source);
    let mut cursor = node.walk();
    let first = node
        .named_children(&mut cursor)
        .find(|c| c.kind() != "comment" && c.kind() != "identifier");
    first.is_some_and(|first| {
        first.kind() == "preproc_def"
            && first
                .child_by_field_name("name")
                .is_some_and(|n| get_node_text(&n, source) == name)
    })
}

/// Whether the byte at `offset` sits on a preprocessor directive's *logical*
/// line: the physical line it is on, or the first line of a backslash-continued
/// run ending in it, begins (ignoring leading whitespace) with `#`.
///
/// The text-level companion to [`is_in_preproc_condition`], and the one to
/// reach for when a rule is misreading a directive. They answer the same
/// question on different inputs and neither subsumes the other:
///
/// - [`is_in_preproc_condition`] asks the *tree*, and is exact when tree-sitter
///   built a `preproc_if` with a `condition` field.
/// - This asks the *source*, and still works when it did not.
///
/// That distinction is the whole point. tree-sitter has no preprocessor, so a
/// directive it cannot place is absorbed into an `ERROR` node — and then there
/// is no `preproc_if`, no `condition` field, and nothing for the tree-level
/// predicate to match. Measured on the real corpus:
/// `is_in_preproc_condition` answers `false` at *every* site where a rule was
/// actually misreading a directive as C, because the parse damage that confuses
/// the rule is the same damage that destroyed the nodes. A directive intact
/// enough for the tree-level check was never the one misfiring. So a rule
/// fixing this class needs this predicate, not that one — see ADR-0008.
///
/// Answers `false` for the guarded BODY of a directive, which is ordinary
/// runtime code: body lines do not start with `#`. That is the same boundary
/// [`is_in_preproc_condition`] draws, and the reason neither is a blanket
/// "is this near a preprocessor" test.
///
/// Continuation lines are followed upward because only the first line of a
/// multi-line `#if A && \` / `B` carries the `#`, and a rule can land on any
/// of them.
///
/// Not folded into `analyze::unknown_identifier_recovery::line_is_preprocessor_directive`
/// or `analyze::embedded_js_blank::on_directive_line`, which look similar: both
/// are pre-parse passes with deliberately different bounds (the latter examines
/// only the text *before* the byte, so it answers `false` when the byte is the
/// `#` itself), and neither follows continuations. Changing them to satisfy a
/// rule-layer caller would alter passes that run before parsing.
pub fn is_on_preproc_directive_line(source: &str, offset: usize) -> bool {
    let offset = offset.min(source.len());
    let mut line_start = source[..offset].rfind('\n').map_or(0, |i| i + 1);

    // Walk up through backslash-continued predecessors to the logical line's
    // real first line, which is the only one carrying the `#`.
    while line_start > 0 {
        let prev_newline = line_start - 1;
        let prev_start = source[..prev_newline].rfind('\n').map_or(0, |i| i + 1);
        // Tolerate trailing whitespace after the backslash: C requires the
        // backslash immediately before the newline, but real headers carry
        // aligned continuations and compilers accept them with a warning.
        if source[prev_start..prev_newline].trim_end().ends_with('\\') {
            line_start = prev_start;
        } else {
            break;
        }
    }

    // Bound the slice to this line. Trimming the rest of the file instead would
    // skip over blank lines and read a later line's `#`.
    let line_end = source[line_start..]
        .find('\n')
        .map_or(source.len(), |i| line_start + i);
    source[line_start..line_end].trim_start().starts_with('#')
}

/// Whether the byte at `offset` lies inside a string or character literal in
/// `source`.
///
/// For when the TREE says a byte is code and the SOURCE says it is text. That
/// disagreement is not hypothetical: tree-sitter has no preprocessor, and a
/// directive it cannot place is absorbed into an `ERROR` node that can swallow
/// the quote delimiters with it. hostap's
/// `wpa_printf(MSG_ERROR, "Line %d: Invalid bss_load_test", line)` then
/// reparses the literal's own contents as C — the `%` of the `%d` conversion
/// specifier becomes a modulo operator and the words around it become its
/// operands, so INT33-C reported "division by 'bss_load_test'" and INT10-C a
/// signed modulo, on a line holding neither (ADR-0008).
///
/// Checking that the operator node exists does not catch this — it does exist,
/// it is simply made of a character that was inside a literal. The only thing
/// that distinguishes the two is the source.
///
/// Comments are tracked so a quote or apostrophe inside one (`/* don't */`)
/// cannot leave the scanner stuck in a literal and suppress every finding after
/// it. A byte inside a comment answers `false`: it is not in a literal, and a
/// node parsed out of a comment is a different pathology.
///
/// Scans from the start of `source`, so it is O(offset). Call it at the point a
/// finding is about to be reported, not while walking every candidate node.
pub fn is_in_string_or_char_literal(source: &str, offset: usize) -> bool {
    let bytes = source.as_bytes();
    let end = offset.min(bytes.len());
    let mut i = 0;
    while i < end {
        match bytes[i] {
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
            }
            quote @ (b'"' | b'\'') => {
                let open = i;
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == quote {
                        break;
                    }
                    // An unterminated literal must not swallow the rest of the
                    // file: a lone apostrophe is ordinary in prose that a
                    // damaged parse may have dragged in.
                    if bytes[i] == b'\n' {
                        break;
                    }
                    i += 1;
                }
                if i >= end {
                    // `offset` fell between the delimiters.
                    return offset > open && i < bytes.len() && bytes[i] == quote;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    false
}

// ============================================================================
// Identifier Extraction from Declarators
// ============================================================================

/// Extract identifier name from a declarator node
/// Handles simple identifiers, pointer declarators, and array declarators
///
/// Examples:
/// - int x           -> "x"
/// - int *ptr        -> "ptr"
/// - int arr\[10\]     -> "arr"
/// - int **ptr       -> "ptr"
/// - int (*fn)(int)  -> "fn"
pub fn get_identifier_from_declarator(declarator: &Node, source: &str) -> String {
    match declarator.kind() {
        "identifier" => get_node_text_owned(declarator, source),
        "pointer_declarator"
        | "array_declarator"
        | "function_declarator"
        | "parenthesized_declarator" => {
            // Recursively search for the identifier
            for i in 0..declarator.child_count() {
                if let Some(child) = declarator.child(i) {
                    if child.kind() == "identifier" {
                        return get_node_text_owned(&child, source);
                    }
                    let nested = get_identifier_from_declarator(&child, source);
                    if !nested.is_empty() {
                        return nested;
                    }
                }
            }
            String::new() // Return empty string for consistency with original implementations
        }
        _ => String::new(), // Return empty string for consistency with original implementations
    }
}

/// Names of the functions declared by an `ERROR` node wrapping declarations
/// tree-sitter could not finish.
///
/// A prototype or definition decorated with a trailing attribute macro
/// (`__THROW`, `__wur`, `__nonnull ((1))`), or interrupted by a preprocessor
/// conditional inside its own declarator, does not parse as a `declaration`
/// or a `function_definition` at all: tree-sitter emits an `ERROR` node whose
/// children are the specifiers, the `function_declarator`, and the undigested
/// tokens. glibc writes most of POSIX that way — every `sigaction`,
/// `sigprocmask` and `setuid` prototype has this shape — so a walk that only
/// visits `declaration`/`function_definition` nodes reads the whole POSIX
/// surface as undeclared. sqlite's `columnNullValue`, whose
/// definition carries a conditional `__attribute__((aligned(8)))`, is the
/// same node shape reached from the other cause.
///
/// Returns *every* such declaration, because one `ERROR` is not always one
/// declaration: recovery in a heavily macro-decorated file can collapse the
/// whole translation unit into a single `ERROR` whose children are its
/// top-level items (pure-ftpd's `src/ftpd.c` does this), and there stopping at
/// the first match would recover one name out of hundreds.
///
/// What is recognized is a run of type/storage specifiers immediately followed
/// by a function declarator — the shape of a declaration and nothing else. Any
/// other child ends the run, so a misparsed *call* recovered inside an `ERROR`,
/// which never has specifiers in front of it, is not read back as a
/// declaration.
///
/// A pointer-returning prototype (`char *strdup(...) __THROW`) is *not*
/// affected — it still parses as a `declaration` — so this is a supplement to
/// the normal declaration walk, never a replacement for it: call it on the
/// `ERROR`, then keep recursing.
pub fn function_names_in_error_declaration(node: &Node, source: &str) -> Vec<String> {
    error_declarations(node, source)
        .into_iter()
        .map(|decl| decl.name)
        .collect()
}

/// One declaration recovered from inside an `ERROR` node: everything the
/// normal `declaration` walk would have given a rule, had tree-sitter managed
/// to build the node.
/// `return_type` and `parameters` have no in-tree consumer yet: nothing
/// stores a *prototype's* parameter types project-wide today
/// (`FunctionSummary` carries parameter indices, not types), so wiring them
/// into a rule needs a `ProjectContext` field that an earlier fix did not scope.
/// They are read by the real-world probe and are the point of the promotion.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ErrorDeclaration {
    /// The declared function's name.
    pub name: String,
    /// The specifier run in front of the declarator, joined with single
    /// spaces (`"static const char *"` loses no token but is not
    /// whitespace-faithful to the source).
    pub return_type: String,
    /// `(name, type)` per parameter, as [`get_function_parameters`] returns
    /// them for a real `declaration`. Empty when the declarator carries no
    /// `parameter_list` the extractor could read.
    ///
    /// CAVEAT for any future consumer: when a parameter list is split by an
    /// `#if`, recovery can merge BOTH arms into one list. hostap's
    /// `wpa_supplicant_ctrl_iface_detach` comes back carrying the
    /// `CONFIG_CTRL_IFACE_UDP_IPV6` token and two different `from`
    /// parameters. The names and types are individually real, but the arity
    /// is not, so this is safe to read a parameter's TYPE from and unsafe to
    /// count.
    pub parameters: Vec<(String, String)>,
}

/// Read every declaration back out of an `ERROR` node -- name, return type
/// and parameter list, where [`function_names_in_error_declaration`] returns
/// only the name.
///
/// RECOGNITION is unchanged in kind: a run of type/storage specifiers
/// immediately followed by a function declarator, and any other sibling ends
/// the run. That guard is what keeps a misparsed *call* out -- recovery
/// reports hostap's `else if (os_strcmp(buf, "rsne_override") == 0)` chain as
/// 34 `function_declarator`s under `parenthesized_declarator`s, and a call
/// never has specifiers in front of it. Two subtrees are skipped outright for
/// the same reason, and because the ordinary walk already covers them:
///
///   * `declaration` -- recovery often keeps a real `declaration` node inside
///     the `ERROR` (raylib's `rgestures.h` holds ten under a
///     `linkage_specification`). Those are not damaged; a walker that
///     recurses through `ERROR` sees them with no help from here.
///   * `parenthesized_declarator` -- the call shape above.
///   * `function_definition` -- it has its own body and declarator, and
///     `get_function_parameters` reads it directly.
///
/// UNLIKE the name-only reader this replaces, the scan RECURSES. The
/// specifier-run shape is not always a direct child of the `ERROR`:
/// measured across the nine pinned real-world checkouts, 37 such declarators
/// sit at depth 1 and 15 deeper, so a direct-children-only scan silently
/// dropped the latter (and the four whose run this now joins across a
/// recovered sibling).
pub fn error_declarations(node: &Node, source: &str) -> Vec<ErrorDeclaration> {
    let mut declarations = Vec::new();
    if node.kind() != "ERROR" {
        return declarations;
    }
    collect_error_declarations(node, source, &mut declarations);
    declarations
}

fn collect_error_declarations(node: &Node, source: &str, out: &mut Vec<ErrorDeclaration>) {
    let mut specifiers: Vec<String> = Vec::new();
    for i in 0..node.child_count() {
        let Some(child) = node.child(i) else {
            continue;
        };
        match child.kind() {
            "storage_class_specifier"
            | "type_qualifier"
            | "primitive_type"
            | "sized_type_specifier"
            | "type_identifier"
            | "struct_specifier"
            | "union_specifier"
            | "enum_specifier" => {
                specifiers.push(get_node_text(&child, source).trim().to_string());
                continue;
            }
            "function_declarator" | "pointer_declarator" if !specifiers.is_empty() => {
                if crate::utility::cert_c::declarator_utils::is_function_declarator(&child) {
                    let name = get_identifier_from_declarator(&child, source);
                    if !name.is_empty() {
                        let stars = pointer_depth(&child);
                        let mut return_type = specifiers.join(" ");
                        if stars > 0 {
                            return_type.push(' ');
                            return_type.extend(std::iter::repeat_n('*', stars));
                        }
                        out.push(ErrorDeclaration {
                            name,
                            return_type,
                            parameters: parameters_of_declarator(&child, source),
                        });
                    }
                }
                specifiers.clear();
                continue;
            }
            // Already-structured, or provably not a declaration -- see the
            // doc comment on `error_declarations`.
            "declaration" | "parenthesized_declarator" | "function_definition" => {
                specifiers.clear();
                continue;
            }
            _ => {}
        }
        specifiers.clear();
        collect_error_declarations(&child, source, out);
    }
}

/// How many `pointer_declarator` layers wrap the `function_declarator`, i.e.
/// the pointer depth of the function's RETURN type.
///
/// The specifier run alone is not the return type. `struct wpa_authenticator *
/// wpa_init(...)` (hostap) puts `struct wpa_authenticator` in the specifiers
/// and the `*` in a `pointer_declarator` around the `function_declarator`, so
/// joining specifiers reports it as returning a struct BY VALUE -- wrong in
/// the one direction that matters, since a consumer would conclude the result
/// cannot be NULL.
fn pointer_depth(declarator: &Node) -> usize {
    if declarator.kind() != "pointer_declarator" {
        return 0;
    }
    let nested = (0..declarator.child_count())
        .filter_map(|i| declarator.child(i))
        .map(|c| pointer_depth(&c))
        .max()
        .unwrap_or(0);
    1 + nested
}

/// The parameters of a `function_declarator`, whether it is the declarator
/// itself or wrapped in a `pointer_declarator` for a pointer-returning
/// function.
fn parameters_of_declarator(declarator: &Node, source: &str) -> Vec<(String, String)> {
    if declarator.kind() == "function_declarator" {
        return extract_parameters(declarator, source).unwrap_or_default();
    }
    for i in 0..declarator.child_count() {
        if let Some(child) = declarator.child(i) {
            let nested = parameters_of_declarator(&child, source);
            if !nested.is_empty() {
                return nested;
            }
        }
    }
    Vec::new()
}

/// Find identifier in a declarator node, returns Option instead of "unknown" string.
///
/// Delegates to [`get_identifier_from_declarator`], which (unlike this
/// function's original implementation) checks the declarator's own node kind
/// before scanning its children — needed for a bare, unwrapped declarator
/// (`int j = 0;`) where the declarator field IS the identifier directly.
/// The old children-only scan returned `None` for that shape, which caused a
/// live regression in CON34-C's OpenMP shared-variable detection.
pub fn find_identifier_in_declarator(declarator: &Node, source: &str) -> Option<String> {
    let name = get_identifier_from_declarator(declarator, source);
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

// ============================================================================
// Function Parameter Extraction
// ============================================================================

/// Extract function parameters as (name, full_type) tuples
/// Returns None if the function has no parameters or parameter list not found
pub fn get_function_parameters(
    function_node: &Node,
    source: &str,
) -> Option<Vec<(String, String)>> {
    let declarator = find_function_declarator(function_node)?;
    extract_parameters(&declarator, source)
}

/// For every function this file defines or declares, the indices of its
/// parameters that carry a `restrict` qualifier (`restrict`, `__restrict`
/// or `__restrict__`, as a `type_qualifier` anywhere in the parameter's
/// declarator chain, so `int *restrict p` and `char *const restrict s` both
/// count). Functions with no restrict parameter are absent. Walks
/// `function_definition` and prototype `declaration` nodes, recursing
/// through preprocessor and linkage blocks; a name declared more than once
/// keeps the first form seen. This is the only fact EXP43-C needs about a
/// callee -- a call that repeats an argument is undefined only if the
/// parameter it lands on is restrict-qualified.
pub fn restrict_parameter_indices(root: &Node, source: &str) -> HashMap<String, Vec<usize>> {
    fn walk(node: &Node, source: &str, out: &mut HashMap<String, Vec<usize>>) {
        for i in 0..node.child_count() {
            let Some(child) = node.child(i) else { continue };
            match child.kind() {
                "function_definition" | "declaration" => {
                    if let Some(declarator) = find_function_declarator(&child) {
                        record_restrict_params(&declarator, source, out);
                    }
                }
                kind if kind.starts_with("preproc_")
                    || kind == "linkage_specification"
                    || kind == "declaration_list"
                    || kind == "ERROR" =>
                {
                    walk(&child, source, out);
                }
                _ => {}
            }
        }
    }
    fn record_restrict_params(
        declarator: &Node,
        source: &str,
        out: &mut HashMap<String, Vec<usize>>,
    ) {
        let Some(name_node) = declarator.child_by_field_name("declarator") else {
            return;
        };
        let name = match name_node.kind() {
            "identifier" => get_node_text(&name_node, source).to_string(),
            "parenthesized_declarator" => get_identifier_from_declarator(&name_node, source),
            _ => return,
        };
        if name.is_empty() {
            return;
        }
        let Some(params) = declarator.child_by_field_name("parameters") else {
            return;
        };
        let indices: Vec<usize> = (0..params.named_child_count())
            .filter_map(|i| params.named_child(i))
            .filter(|p| p.kind() == "parameter_declaration")
            .enumerate()
            .filter(|(_, p)| {
                query::find_first_descendant(*p, |n| {
                    n.kind() == "type_qualifier"
                        && matches!(
                            get_node_text(&n, source),
                            "restrict" | "__restrict" | "__restrict__"
                        )
                })
                .is_some()
            })
            .map(|(i, _)| i)
            .collect();
        if !indices.is_empty() {
            out.entry(name).or_insert(indices);
        }
    }
    let mut out = HashMap::new();
    walk(root, source, &mut out);
    out
}

/// For every function this file defines or declares under a doc comment,
/// the indices of the pointer parameters that comment states a non-NULL
/// precondition for: a `\param`/`@param` block saying the argument "must
/// be initialized", "must not be NULL", "must point to a valid ...",
/// "non-NULL" and the like (the exact wording set is `states_nonnull`).
///
/// This is the function's own published contract -- the one place a
/// caller-side validation discipline is written down -- and the reason
/// API00-C and EXP34-C stop reporting mbedtls's `ctx`/`operation` parameters
/// . Deliberately NOT a caller-behaviour inference
/// (measured wrong 87% of the time): a parameter whose doc
/// merely describes it ("The AES context to use") is not covered.
pub fn documented_nonnull_parameters(root: &Node, source: &str) -> HashMap<String, Vec<usize>> {
    fn walk(node: &Node, source: &str, out: &mut HashMap<String, Vec<usize>>) {
        let mut prev_comment: Option<Node> = None;
        for i in 0..node.child_count() {
            let Some(child) = node.child(i) else { continue };
            match child.kind() {
                "comment" => {
                    prev_comment = Some(child);
                    continue;
                }
                "function_definition" | "declaration" => {
                    if let Some(comment) = prev_comment
                        .filter(|c| c.end_position().row + 2 >= child.start_position().row)
                    {
                        record_documented_params(&child, &comment, source, out);
                    }
                }
                kind if kind.starts_with("preproc_")
                    || kind == "linkage_specification"
                    || kind == "declaration_list" =>
                {
                    walk(&child, source, out);
                }
                _ => {}
            }
            prev_comment = None;
        }
    }
    fn record_documented_params(
        decl: &Node,
        comment: &Node,
        source: &str,
        out: &mut HashMap<String, Vec<usize>>,
    ) {
        let Some(declarator) = find_function_declarator(decl) else {
            return;
        };
        let Some(name_node) = declarator.child_by_field_name("declarator") else {
            return;
        };
        let name = match name_node.kind() {
            "identifier" => get_node_text(&name_node, source).to_string(),
            "parenthesized_declarator" => get_identifier_from_declarator(&name_node, source),
            _ => return,
        };
        let Some(params) = declarator.child_by_field_name("parameters") else {
            return;
        };
        let text = get_node_text(comment, source);
        if !text.starts_with("/**") && !text.starts_with("/*!") && !text.starts_with("///") {
            return;
        }
        let blocks = doc_param_blocks(text);
        if blocks.is_empty() {
            return;
        }
        let indices: Vec<usize> = (0..params.named_child_count())
            .filter_map(|i| params.named_child(i))
            .filter(|p| p.kind() == "parameter_declaration")
            .enumerate()
            .filter(|(_, p)| {
                p.child_by_field_name("declarator")
                    .map(|d| get_identifier_from_declarator(&d, source))
                    .filter(|n| !n.is_empty())
                    .and_then(|n| blocks.get(&n))
                    .is_some_and(|block| states_nonnull(block))
            })
            .map(|(i, _)| i)
            .collect();
        if !indices.is_empty() {
            let entry = out.entry(name).or_default();
            for i in indices {
                if !entry.contains(&i) {
                    entry.push(i);
                }
            }
        }
    }
    let mut out = HashMap::new();
    walk(root, source, &mut out);
    out
}

/// The `\param NAME text...` blocks of a Doxygen comment, keyed by NAME,
/// each block running to the next Doxygen command. Comment-line decoration
/// (`*` margins) is stripped and whitespace collapsed.
fn doc_param_blocks(comment: &str) -> HashMap<String, String> {
    let cleaned: String = comment
        .lines()
        .map(|l| {
            l.trim()
                .trim_start_matches("/**")
                .trim_start_matches("/*!")
                .trim_start_matches("///")
                .trim_start_matches('*')
                .trim_end_matches("*/")
        })
        .collect::<Vec<_>>()
        .join(" ");
    let mut blocks = HashMap::new();
    let mut rest = cleaned.as_str();
    while let Some(pos) = rest.find("param") {
        let is_command = pos > 0 && matches!(rest.as_bytes()[pos - 1], b'\\' | b'@');
        let after = &rest[pos + "param".len()..];
        if !is_command {
            rest = after;
            continue;
        }
        // Optional `[in]`, `[out]`, `[in,out]`.
        let after = after.trim_start();
        let after = match after.strip_prefix('[') {
            Some(t) => t.split_once(']').map(|(_, t)| t).unwrap_or(""),
            None => after,
        };
        let after = after.trim_start();
        let name_end = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(after.len());
        let (name, body) = after.split_at(name_end);
        // The block ends at the next Doxygen command other than the inline
        // `\c` / `\p` formatting ones.
        let end = body
            .char_indices()
            .find(|&(i, c)| {
                if c != '\\' && c != '@' {
                    return false;
                }
                let word: String = body[i + 1..]
                    .chars()
                    .take_while(|n| n.is_ascii_alphabetic())
                    .collect();
                !word.is_empty() && word != "c" && word != "p"
            })
            .map(|(i, _)| i)
            .unwrap_or(body.len());
        if !name.is_empty() {
            blocks
                .entry(name.to_string())
                .or_insert_with(|| body[..end].split_whitespace().collect::<Vec<_>>().join(" "));
        }
        rest = &body[end..];
    }
    blocks
}

/// Whether a parameter's doc block states that the argument must be valid
/// and non-NULL.
fn states_nonnull(block: &str) -> bool {
    let t = block
        .to_ascii_lowercase()
        .replace("\\c ", "")
        .replace("\\p ", "")
        .replace("@c ", "");
    [
        "must be initialized",
        "must have been initialized",
        "must be a valid",
        "must be an initialized",
        "must point to",
        "must be non-null",
        "must not be null",
        "must be a non-null",
        "must be a pointer to",
        "must be the address of",
        "must be a readable",
        "must be a writable",
        "must be a writeable",
        "must be readable",
        "must be writable",
        "must be writeable",
        "non-null",
        "cannot be null",
        "may not be null",
        "shall not be null",
    ]
    .iter()
    .any(|w| t.contains(w))
}

/// The declared names of a function's parameters in declaration order, an
/// empty string where a parameter has no name -- the same enumeration
/// [`restrict_parameter_indices`] and [`documented_nonnull_parameters`]
/// index by, so an index from either maps back to a name through this.
pub fn ordered_parameter_names(function_node: &Node, source: &str) -> Vec<String> {
    let Some(params) =
        find_function_declarator(function_node).and_then(|d| d.child_by_field_name("parameters"))
    else {
        return Vec::new();
    };
    (0..params.named_child_count())
        .filter_map(|i| params.named_child(i))
        .filter(|p| p.kind() == "parameter_declaration")
        .map(|p| {
            p.child_by_field_name("declarator")
                .map(|d| get_identifier_from_declarator(&d, source))
                .unwrap_or_default()
        })
        .collect()
}

/// Find the `function_declarator` in a function's declarator subtree. For a
/// function returning a non-pointer type it is a direct child of the
/// `function_definition`; for a pointer-returning function (`char *
/// name(...)`) it is nested one level deeper inside a `pointer_declarator`,
/// which the previous direct-children-only scan missed entirely.
fn find_function_declarator<'a>(function_node: &Node<'a>) -> Option<Node<'a>> {
    for i in 0..function_node.child_count() {
        let child = function_node.child(i)?;
        match child.kind() {
            "function_declarator" => return Some(child),
            "pointer_declarator" => {
                if let Some(found) = find_function_declarator(&child) {
                    return Some(found);
                }
            }
            _ => {}
        }
    }
    None
}

/// Extract parameters from a function declarator node
fn extract_parameters(declarator_node: &Node, source: &str) -> Option<Vec<(String, String)>> {
    let mut parameters = Vec::new();

    // Find parameter_list node
    for i in 0..declarator_node.child_count() {
        if let Some(child) = declarator_node.child(i) {
            if child.kind() == "parameter_list" {
                // Extract each parameter
                for j in 0..child.child_count() {
                    if let Some(param) = child.child(j) {
                        if param.kind() == "parameter_declaration" {
                            if let Some((name, param_type)) = extract_parameter_info(&param, source)
                            {
                                parameters.push((name, param_type));
                            }
                        }
                    }
                }
            }
        }
    }

    if parameters.is_empty() {
        None
    } else {
        Some(parameters)
    }
}

/// Extract parameter information (name and type) from a parameter declaration
fn extract_parameter_info(param_node: &Node, source: &str) -> Option<(String, String)> {
    let param_text = get_node_text(param_node, source);

    // Look for declarator pattern
    for i in 0..param_node.child_count() {
        if let Some(child) = param_node.child(i) {
            if matches!(
                child.kind(),
                "array_declarator" | "pointer_declarator" | "function_declarator"
            ) {
                // Found array, pointer, or function pointer parameter
                if let Some(identifier) = find_identifier_in_declarator(&child, source) {
                    return Some((identifier, param_text.to_string()));
                }
            } else if child.kind() == "identifier" {
                // Simple parameter
                let name = get_node_text(&child, source);
                return Some((name.to_string(), param_text.to_string()));
            }
        }
    }

    None
}

/// Check if a variable name appears in the function's parameter list
pub fn is_function_parameter(function_node: &Node, var_name: &str, source: &str) -> bool {
    // Find parameter list in function
    for i in 0..function_node.child_count() {
        if let Some(child) = function_node.child(i) {
            if child.kind() == "function_declarator" {
                for j in 0..child.child_count() {
                    if let Some(param_list) = child.child(j) {
                        if param_list.kind() == "parameter_list" {
                            let param_text = get_node_text(&param_list, source);
                            // Check for word boundaries to avoid substring matches
                            let words: Vec<&str> = param_text
                                .split(|c: char| !c.is_alphanumeric() && c != '_')
                                .collect();
                            if words.contains(&var_name) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

// ============================================================================
// Type Checking Utilities
// ============================================================================

/// Check if a parameter type string indicates an array parameter
pub fn is_array_parameter_type(param_type: &str) -> bool {
    param_type.contains('[') || (param_type.contains('*') && !param_type.contains("const char *"))
}

/// Check if a type string represents a pointer type
pub fn is_pointer_type(type_str: &str) -> bool {
    type_str.contains('*')
}

/// Check if a type string represents a generic (non-pointer-storage) integer
/// type: `int`/`unsigned`/`long`/`short`/`char`/`size_t`/`ptrdiff_t`, but NOT
/// `uintptr_t`/`intptr_t` (those are pointer-storage-safe integer types, a
/// distinct concept from "is this an integer at all").
pub fn is_integer_type(type_str: &str) -> bool {
    const INTEGER_TYPES: &[&str] = &[
        "int",
        "unsigned",
        "long",
        "short",
        "char",
        "size_t",
        "ptrdiff_t",
    ];
    INTEGER_TYPES.iter().any(|&t| {
        type_str.contains(t) && !type_str.contains("uintptr_t") && !type_str.contains("intptr_t")
    })
}

/// Check if a type string represents a signed integer type
#[allow(dead_code)]
pub fn is_signed_type(type_str: &str) -> bool {
    matches!(
        type_str.trim(),
        "int"
            | "short"
            | "long"
            | "char"
            | "signed"
            | "signed int"
            | "signed short"
            | "signed long"
            | "long long"
            | "signed long long"
            | "signed char"
            | "int8_t"
            | "int16_t"
            | "int32_t"
            | "int64_t"
            | "ptrdiff_t"
            | "ssize_t"
    )
}

/// The bit-width of a known integer type name, or `None` when the spelling is
/// not one this table recognizes (a typedef out of a header, a struct, a
/// pointer).
///
/// Exact-match on the trimmed spelling, and the 64-bit family is tested before
/// the 32-bit one so `long int` cannot match `int`. Widths are the pinned
/// x86_64 LP64 model the benchmark corpus is built for.
///
/// Callers use this to *suppress*, so an unrecognized spelling answering
/// `None` keeps whatever the caller would otherwise report.
pub fn integer_type_width(type_str: &str) -> Option<u32> {
    let t = type_str.trim();

    if t == "char" || t == "signed char" || t == "unsigned char" || t == "int8_t" || t == "uint8_t"
    {
        return Some(8);
    }

    if t == "short"
        || t == "signed short"
        || t == "unsigned short"
        || t == "short int"
        || t == "signed short int"
        || t == "unsigned short int"
        || t == "int16_t"
        || t == "uint16_t"
    {
        return Some(16);
    }

    // 64-bit types — check BEFORE 32-bit so "long int" doesn't match "int"
    if t == "long"
        || t == "signed long"
        || t == "unsigned long"
        || t == "long int"
        || t == "signed long int"
        || t == "unsigned long int"
        || t == "long long"
        || t == "signed long long"
        || t == "unsigned long long"
        || t == "long long int"
        || t == "signed long long int"
        || t == "unsigned long long int"
        || t == "int64_t"
        || t == "uint64_t"
        || t == "size_t"
        || t == "ssize_t"
        || t == "ptrdiff_t"
        || t == "intptr_t"
        || t == "uintptr_t"
    {
        return Some(64);
    }

    if t == "int"
        || t == "signed"
        || t == "unsigned"
        || t == "signed int"
        || t == "unsigned int"
        || t == "int32_t"
        || t == "uint32_t"
    {
        return Some(32);
    }

    None
}

/// Check if a type string represents an unsigned integer type.
///
/// Besides the C spellings, the Win32 SDK's fixed unsigned typedef names
/// (`DWORD`, `UINT32`, `ULONG_PTR`, ...) are recognised by name: they are
/// defined in headers the scan never reads, so no typedef chain can reach
/// them, and without this a `(UINT32)strlen(s) + 1` allocation size was
/// signed to one rule and untyped to the other, so neither reported it
/// (ventoy).
#[allow(dead_code)]
pub fn is_unsigned_type(type_str: &str) -> bool {
    type_str.contains("unsigned")
        || matches!(
            type_str.trim(),
            "size_t" | "uint8_t" | "uint16_t" | "uint32_t" | "uint64_t" | "uintptr_t" | "uintmax_t"
        )
        || is_win32_unsigned_typedef(type_str.trim())
}

/// The Win32 SDK's unsigned integer typedef names, as spelled in
/// `<windows.h>` / `<basetsd.h>`. A fixed vocabulary, not a shape.
pub fn is_win32_unsigned_typedef(type_str: &str) -> bool {
    matches!(
        type_str,
        "BYTE"
            | "UCHAR"
            | "WORD"
            | "USHORT"
            | "DWORD"
            | "DWORD32"
            | "DWORD64"
            | "DWORDLONG"
            | "UINT"
            | "UINT8"
            | "UINT16"
            | "UINT32"
            | "UINT64"
            | "ULONG"
            | "ULONG32"
            | "ULONG64"
            | "ULONGLONG"
            | "QWORD"
            | "SIZE_T"
            | "ULONG_PTR"
            | "DWORD_PTR"
            | "UINT_PTR"
            | "UINT_FAST8_T"
            | "UINT_FAST16_T"
            | "UINT_FAST32_T"
            | "UINT_FAST64_T"
    )
}

// ============================================================================
// Operator Extraction
// ============================================================================

/// Extract the operator from a binary expression node
pub fn get_binary_operator<'a>(node: &Node, source: &'a str) -> Option<&'a str> {
    // The operator is usually a child of the binary expression
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            let kind = child.kind();
            // Check if this is an operator token
            if matches!(
                kind,
                "+" | "-"
                    | "*"
                    | "/"
                    | "%"
                    | "=="
                    | "!="
                    | "<"
                    | ">"
                    | "<="
                    | ">="
                    | "&&"
                    | "||"
                    | "&"
                    | "|"
                    | "^"
                    | "<<"
                    | ">>"
                    | "="
                    | "+="
                    | "-="
                    | "*="
                    | "/="
                    | "%="
                    | "&="
                    | "|="
                    | "^="
                    | "<<="
                    | ">>="
            ) {
                return Some(get_node_text(&child, source));
            }
        }
    }
    None
}

// ============================================================================
// Array Size Extraction
// ============================================================================

/// Find array size from declaration in preceding text
/// Looks for patterns like: type array_name\[size\]
/// Returns the size if found and it's a constant
#[allow(dead_code)]
pub fn find_array_size(array_name: &str, preceding_text: &str) -> Option<usize> {
    // Look for array declaration pattern: array_name[number]
    let pattern = format!("{}[", array_name);

    if let Some(pos) = preceding_text.rfind(&pattern) {
        // Extract the size between [ and ]
        let after_bracket = &preceding_text[pos + pattern.len()..];
        if let Some(close_bracket) = after_bracket.find(']') {
            let size_str = after_bracket[..close_bracket].trim();

            // Try to parse as a number
            if let Ok(size) = size_str.parse::<usize>() {
                return Some(size);
            }

            // Try to handle simple arithmetic expressions like 2*3 or 10+5
            if size_str.contains('*') {
                let parts: Vec<&str> = size_str.split('*').collect();
                if parts.len() == 2 {
                    if let (Ok(a), Ok(b)) = (
                        parts[0].trim().parse::<usize>(),
                        parts[1].trim().parse::<usize>(),
                    ) {
                        return Some(a * b);
                    }
                }
            }
        }
    }

    None
}

/// Get the size of a C type in bytes
/// This is a best-effort approximation for common types
#[allow(dead_code)]
pub fn get_type_size(type_name: &str) -> usize {
    match type_name.trim() {
        "char" | "signed char" | "unsigned char" | "int8_t" | "uint8_t" => 1,
        "short" | "signed short" | "unsigned short" | "int16_t" | "uint16_t" => 2,
        "int" | "signed int" | "unsigned int" | "int32_t" | "uint32_t" | "float" => 4,
        "long" | "signed long" | "unsigned long" | "long long" | "signed long long"
        | "unsigned long long" | "int64_t" | "uint64_t" | "double" | "size_t" | "ptrdiff_t" => 8,
        "long double" => 16,
        t if t.ends_with('*') => 8, // Pointer size on 64-bit
        _ => 4,                     // Default to int size
    }
}

// ============================================================================
// Context Analysis
// ============================================================================

/// Check if a subscript expression is on the left side of an assignment (write context)
/// Handles nested subscripts like matrix\[i\]\[j\] = value
pub fn is_write_context(node: &Node) -> bool {
    let mut current = *node;

    // Walk up the tree while we're in subscript expressions
    loop {
        if let Some(parent) = current.parent() {
            if parent.kind() == "assignment_expression" {
                // Check if current node (or its ancestor subscript) is the left side
                if let Some(left) = parent.child_by_field_name("left") {
                    return left.id() == current.id();
                }
                return false;
            } else if parent.kind() == "subscript_expression" {
                // Keep walking up through nested subscripts
                current = parent;
            } else {
                // Hit a different node type, not a write context
                return false;
            }
        } else {
            // No parent, not a write context
            return false;
        }
    }
}

/// The identifier sitting in the "type" position of a cast that
/// `tree-sitter-c` mis-parsed as something else, or `None` when `node` is not
/// one of those shapes.
///
/// Whether `(N)&x` is a cast or a bitwise AND depends on whether `N` names a
/// type -- the C grammar cannot decide it without a typedef table, and
/// `tree-sitter-c` does not consult one here. Measured, for
/// `typedef word_t seL4_Word;` declared in the same file:
///
/// ```text
///   (seL4_Word)x     cast_expression                      <- the only one that works
///   (seL4_Word)&x    binary_expression   left: (T)  op &
///   (seL4_Word)*p    binary_expression   left: (T)  op *
///   (seL4_Word)-y    binary_expression   left: (T)  op -
///   (seL4_Word)+y    binary_expression   left: (T)  op +
///   (seL4_Word)(x)   call_expression     function: (T)
/// ```
///
/// The parse is IDENTICAL with the typedef absent, so this is not a matter of
/// the typedef being out of scope in a per-file parse -- there is no scanner
/// state to pre-seed, and no amount of cross-file typedef knowledge reaches
/// it. Recognising the shape after the fact is the only available fix
/// .
///
/// Deliberately PURELY STRUCTURAL: it returns the name whatever it is, and the
/// caller must confirm the name is a typedef before treating the node as a
/// cast. `(mask) & flags` has exactly this shape and is a real bitwise AND
/// when `mask` is a variable, so the type knowledge -- which is per-rule and
/// sometimes cross-file -- has to stay with the caller.
pub fn misparsed_cast_type_name<'a>(node: &Node, source: &'a str) -> Option<&'a str> {
    let candidate = match node.kind() {
        // `(T)&x` and friends: the "type" lands in the left operand.
        "binary_expression" => {
            let op = node.child_by_field_name("operator")?;
            if !matches!(get_node_text(&op, source), "&" | "*" | "-" | "+") {
                return None;
            }
            node.child_by_field_name("left")?
        }
        // `(T)(x)`: the "type" lands in the callee position.
        "call_expression" => node.child_by_field_name("function")?,
        _ => return None,
    };

    if candidate.kind() != "parenthesized_expression" {
        return None;
    }
    // Exactly one named child, and it is a bare identifier -- `(a + b) & c`
    // and `(s->mask) & c` are ordinary expressions, not mis-parsed casts.
    if candidate.named_child_count() != 1 {
        return None;
    }
    let inner = candidate.named_child(0)?;
    if inner.kind() != "identifier" {
        return None;
    }
    Some(get_node_text(&inner, source))
}

/// Check if a node is part of a sizeof expression
pub fn is_in_sizeof(node: &Node) -> bool {
    query::nearest_ancestor_of_kind(*node, "sizeof_expression").is_some()
}

// ============================================================================
// Control Flow Navigation Utilities
// ============================================================================

/// Find the containing for loop statement for a given node
///
/// # Arguments
/// * `node` - The starting node to search from
///
/// # Returns
/// The for_statement node that contains the given node, or None if not found
///
/// # Examples
/// ```no_run
/// use aurora_lint::utility::cert_c::ast_utils::find_containing_for_loop;
/// use tree_sitter::Node;
/// // When checking a subscript inside a for loop:
/// // let subscript_node: Node = /* get from parsed AST */;
/// // if let Some(for_loop) = find_containing_for_loop(&subscript_node) {
/// //     // Analyze loop bounds
/// // }
/// ```
pub fn find_containing_for_loop<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    query::nearest_ancestor_of_kind(*node, "for_statement")
}

/// Find the containing if statement for a given node
///
/// # Arguments
/// * `node` - The starting node to search from
///
/// # Returns
/// The if_statement node that contains the given node, or None if not found
///
/// # Examples
/// ```no_run
/// use aurora_lint::utility::cert_c::ast_utils::find_containing_if_statement;
/// use tree_sitter::Node;
/// // When checking if array access is within a bounds check:
/// // let subscript_node: Node = /* get from parsed AST */;
/// // if let Some(if_stmt) = find_containing_if_statement(&subscript_node) {
/// //     // Check if condition validates bounds
/// // }
/// ```
pub fn find_containing_if_statement<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    query::nearest_ancestor_of_kind(*node, "if_statement")
}

// ============================================================================
// Struct Type Resolution
// ============================================================================

/// Extract the struct name from a C type string.
///
/// Handles patterns like:
/// - `"struct MyStruct *"` → `Some("MyStruct")`
/// - `"struct MyStruct"` → `Some("MyStruct")`
/// - `"MyStruct *"` → `Some("MyStruct")`
/// - `"MyStruct"` → `Some("MyStruct")`
/// - `"int"` → `None` (primitive type, not a struct)
///
/// For typedef'd structs (e.g., `typedef struct Foo { ... } Foo;`), the
/// type_map entry may be just `"Foo *"` without the `struct` keyword.
pub fn extract_struct_name_from_type(type_str: &str) -> Option<&str> {
    let trimmed = type_str.trim();

    // Strip pointer/const/volatile qualifiers from both ends
    let mut base = trimmed
        .trim_end_matches('*')
        .trim_end()
        .trim_end_matches("const")
        .trim_end_matches("volatile")
        .trim();
    loop {
        let next = base
            .strip_prefix("const ")
            .or_else(|| base.strip_prefix("volatile "))
            .unwrap_or(base)
            .trim();
        if next == base {
            break;
        }
        base = next;
    }

    // Skip obvious primitives
    if matches!(
        base,
        "int"
            | "unsigned int"
            | "signed int"
            | "short"
            | "unsigned short"
            | "long"
            | "unsigned long"
            | "long long"
            | "unsigned long long"
            | "char"
            | "unsigned char"
            | "signed char"
            | "float"
            | "double"
            | "void"
            | "_Bool"
    ) {
        return None;
    }
    // Skip stdint types
    if base.ends_with("_t")
        && (base.starts_with("int") || base.starts_with("uint") || base.starts_with("size"))
    {
        return None;
    }

    // "struct MyStruct" → "MyStruct"
    if let Some(name) = base.strip_prefix("struct ") {
        let name = name.trim();
        if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Some(name);
        }
        return None;
    }

    // Bare identifier (typedef'd name) — must look like an identifier, not a primitive
    if !base.is_empty()
        && base
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
        && base.chars().all(|c| c.is_alphanumeric() || c == '_')
    {
        return Some(base);
    }

    None
}

/// Resolve the type of a `field_expression` node using the variable type map
/// and struct field type database.
///
/// Given `s->count` where `s` is declared as `struct MyStruct *s`:
/// 1. Extracts field name "count" from the field_expression
/// 2. Looks up base variable "s" → "struct MyStruct *" in type_map
/// 3. Extracts struct name "MyStruct"
/// 4. Looks up "MyStruct"."count" → "int" in struct_field_types
pub fn resolve_field_expression_type(
    node: &Node,
    source: &str,
    type_map: &std::collections::HashMap<String, String>,
    struct_field_types: &std::collections::HashMap<
        String,
        std::collections::HashMap<String, String>,
    >,
) -> Option<String> {
    let field_node = node.child_by_field_name("field")?;
    let field_name = field_node.utf8_text(source.as_bytes()).ok()?;
    let argument = node.child_by_field_name("argument")?;

    // Resolve the struct type of the argument. Supports chained access
    // (`a.b.c`, `a->b.c`) by recursing through nested field_expressions.
    let base_type = match argument.kind() {
        "identifier" => {
            let base_name = argument.utf8_text(source.as_bytes()).ok()?;
            type_map.get(base_name)?.clone()
        }
        "field_expression" => {
            resolve_field_expression_type(&argument, source, type_map, struct_field_types)?
        }
        "pointer_expression" => {
            // `*p.field` — dereference one pointer level from `p`'s type.
            let inner = argument.child_by_field_name("argument")?;
            let inner_name = inner.utf8_text(source.as_bytes()).ok()?;
            let t = type_map.get(inner_name)?;
            t.strip_suffix(" *")
                .or_else(|| t.strip_suffix('*'))
                .map(|s| s.trim().to_string())?
        }
        _ => return None,
    };

    let struct_name = extract_struct_name_from_type(&base_type)?;

    struct_field_types
        .get(struct_name)
        .and_then(|fields| fields.get(field_name))
        .cloned()
}

/// Result of inspecting a `struct_specifier` for packed-ness.
pub enum PackedSignal {
    /// Not packed (or no signal found).
    No,
    /// Directly `__attribute__((packed))` on the specifier — resolved
    /// without needing any other file's context.
    Direct,
    /// A trailing bare identifier between the closing brace and the
    /// terminating `;`/field name (e.g. `struct foo { ... } STRUCT_PACKED;`)
    /// that *might* be a packed-attribute macro — its `#define` may live in
    /// a different file (a header this one doesn't textually include in
    /// aurora-lint's no-preprocessor model), so the caller must resolve the name
    /// against a project-wide macro-name set.
    MacroCandidate(String),
}

/// Inspect `struct_specifier` (a struct *definition*, with a body) for a
/// packed-attribute signal. Some C parsers have no preprocessor, so a
/// trailing macro token like hostap's `STRUCT_PACKED` gets parsed as if it
/// were a declarator/field name rather than an attribute — the caller
/// resolves that candidate name against `#define`s collected project-wide
/// (see `macro_expands_to_packed`), which keeps this codebase-independent
/// rather than a hardcoded name heuristic.
pub fn struct_specifier_packed_signal(s: &Node, source: &str) -> PackedSignal {
    for attr in query::find_descendants_of_kind(*s, "attribute_specifier") {
        if get_node_text(&attr, source).contains("packed") {
            return PackedSignal::Direct;
        }
    }
    let Some(parent) = s.parent() else {
        return PackedSignal::No;
    };
    if !matches!(
        parent.kind(),
        "declaration" | "field_declaration" | "type_definition"
    ) {
        return PackedSignal::No;
    }
    let parent_text = get_node_text(&parent, source);
    let struct_text = get_node_text(s, source);
    let Some(tail) = parent_text.strip_prefix(struct_text) else {
        return PackedSignal::No;
    };
    let Ok(ident_re) = regex::Regex::new(r"[A-Za-z_][A-Za-z0-9_]*") else {
        return PackedSignal::No;
    };
    match ident_re.find(tail) {
        Some(m) => PackedSignal::MacroCandidate(m.as_str().to_string()),
        None => PackedSignal::No,
    }
}

/// True if `struct_specifier` is packed, resolving any trailing-macro
/// candidate against `#define`s in this SAME `source` text only. Used by
/// the single-file/intra-file prescan path (test fixtures); the cross-file
/// prescan path resolves `MacroCandidate`s against a project-wide macro-name
/// set instead (see `analyze::prescan::collect_packed_structs`).
pub fn struct_specifier_is_packed(s: &Node, source: &str) -> bool {
    match struct_specifier_packed_signal(s, source) {
        PackedSignal::Direct => true,
        PackedSignal::MacroCandidate(name) => macro_expands_to_packed(&name, source),
        PackedSignal::No => false,
    }
}

/// True if `#define name ...` appears in `source` and its replacement text
/// contains "packed" (e.g. `#define STRUCT_PACKED __attribute__
/// ((packed))`).
pub fn macro_expands_to_packed(name: &str, source: &str) -> bool {
    let Ok(re) = regex::Regex::new(&format!(
        r"(?m)^\s*#\s*define\s+{}\b.*$",
        regex::escape(name)
    )) else {
        return false;
    };
    re.find(source)
        .map(|m| m.as_str().contains("packed"))
        .unwrap_or(false)
}

/// `#define NAME <body>` lines, compiled once. Group 1 is the macro name,
/// group 2 the rest of the line. The three per-file `#define` sweeps below
/// each ran on every prescanned file, and compiling a fresh `Regex` per call
/// cost more than the matching itself.
fn define_line_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?m)^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b([^\n]*)$").unwrap()
    })
}

/// Collect every `#define NAME ...` object-macro name in `source` whose
/// replacement text contains "packed" (e.g. hostap's `#define STRUCT_PACKED
/// __attribute__ ((packed))`). Plain regex over raw text, not AST-based —
/// deliberately independent of any single file's struct definitions so it
/// can be merged project-wide and used to resolve `PackedSignal::MacroCandidate`s
/// found in *other* files.
pub fn collect_packed_macro_names(source: &str, out: &mut std::collections::HashSet<String>) {
    for cap in define_line_re().captures_iter(source) {
        let line = cap.get(0).map(|m| m.as_str()).unwrap_or("");
        if line.contains("packed") {
            if let Some(name) = cap.get(1) {
                out.insert(name.as_str().to_string());
            }
        }
    }
}

/// True if `#define name ...` appears anywhere in `source`, regardless of
/// what it expands to. Used to recognize a trailing bare identifier right
/// after a struct/union/enum body (e.g. `struct foo { ... } SOME_MACRO;`) as
/// an attribute-position macro invocation rather than a genuine object
/// declaration: aurora-lint has no preprocessor, so such a macro is parsed as if it
/// were the declared object's name, but a real C identifier can never
/// collide with an in-scope `#define` name (the preprocessor would have
/// substituted it first) — so if the name is a known macro, this can't be a
/// real declaration (DCL40-C an earlier fix).
pub fn is_defined_macro_name(name: &str, source: &str) -> bool {
    let Ok(re) = regex::Regex::new(&format!(r"(?m)^\s*#\s*define\s+{}\b", regex::escape(name)))
    else {
        return false;
    };
    re.is_match(source)
}

/// True if `name` looks like a preprocessor macro constant *by naming
/// convention alone*: ALL_CAPS letters, digits and underscores only, and not
/// starting with a digit (so a bare numeric literal is never mistaken for a
/// macro name). Empty input is never a macro name.
///
/// This never consults an actual `#define` — prefer
/// `is_defined_macro_name` (or `ProjectContext`'s project-wide macro-name
/// set) whenever the definition is reachable, and prefer
/// `analyze::macro_expand` whenever the macro's *value* matters. This is the
/// last-resort guess for "is this identifier a compile-time constant?" when
/// no definition is in scope — e.g. distinguishing `int a[SIZE]` (not a VLA)
/// from `int a[n]` (a VLA).
///
/// Single source of truth for a heuristic that was independently
/// reimplemented in five rules with slightly different edge cases:
/// MEM05-C, ARR32-C, MEM33-C, DCL03-C, EXP08-C.
///
/// # Examples
/// ```
/// use aurora_lint::utility::cert_c::ast_utils::is_likely_macro_constant;
/// assert!(is_likely_macro_constant("MAX_SIZE"));
/// assert!(is_likely_macro_constant("_BUF_LEN2"));
/// assert!(!is_likely_macro_constant("bufLen"));
/// assert!(!is_likely_macro_constant("10"));
/// assert!(!is_likely_macro_constant(""));
/// ```
pub fn is_likely_macro_constant(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
}

/// Collect every `#define NAME ...` object-macro name in `source`,
/// regardless of what it expands to. Plain regex over raw text, not
/// AST-based — deliberately independent of any single file's declarations
/// so it can be merged project-wide and used to resolve a trailing bare
/// identifier found in *other* files against the macro's actual `#define`
/// (which commonly lives in a different header, e.g. hostap's
/// `STRUCT_PACKED` in `utils/common.h` vs. structs in
/// `common/ieee802_11_defs.h`). Generalizes `collect_packed_macro_names` to
/// any macro name, not just packed-attribute ones — see `is_defined_macro_name`.
pub fn collect_defined_macro_names(source: &str, out: &mut std::collections::HashSet<String>) {
    for cap in define_line_re().captures_iter(source) {
        if let Some(name) = cap.get(1) {
            out.insert(name.as_str().to_string());
        }
    }
}

/// True if `name` is a C keyword.
///
/// Single source of truth for the check, shared by
/// `analyze::unknown_identifier_recovery` (which must never blank a keyword
/// stranded in an `ERROR` node) and by rules that read a declared name out
/// of a recovered parse. A keyword appearing where an identifier belongs is
/// always a parse artifact, never a real name — the C grammar reserves
/// these, so no declaration can ever bind one.
pub fn is_c_keyword(name: &str) -> bool {
    matches!(
        name,
        "auto"
            | "break"
            | "case"
            | "char"
            | "const"
            | "continue"
            | "default"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "extern"
            | "float"
            | "for"
            | "goto"
            | "if"
            | "inline"
            | "int"
            | "long"
            | "register"
            | "restrict"
            | "return"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "struct"
            | "switch"
            | "typedef"
            | "union"
            | "unsigned"
            | "void"
            | "volatile"
            | "while"
            | "_Alignas"
            | "_Alignof"
            | "_Atomic"
            | "_Bool"
            | "_Complex"
            | "_Generic"
            | "_Imaginary"
            | "_Noreturn"
            | "_Static_assert"
            | "_Thread_local"
    )
}

/// The exact attribute spellings that mean "this may legitimately go
/// unused" — GCC/clang's `unused` attribute in each of its accepted forms,
/// and C23/C++'s `maybe_unused`. Matched as whole tokens, which is what
/// keeps `warn_unused_result` (one token, not `unused`) out.
const UNUSED_ATTRIBUTE_TOKENS: &[&str] = &[
    "unused",
    "__unused",
    "__unused__",
    "maybe_unused",
    "__maybe_unused",
    "__maybe_unused__",
];

/// True if `text` contains an unused-attribute token as a whole token.
fn mentions_unused_attribute_token(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if is_ident_start_char(chars[i]) {
            let start = i;
            while i < chars.len() && is_ident_body_char(chars[i]) {
                i += 1;
            }
            let tok: String = chars[start..i].iter().collect();
            if UNUSED_ATTRIBUTE_TOKENS.contains(&tok.as_str()) {
                return true;
            }
        } else {
            i += 1;
        }
    }
    false
}

fn is_ident_start_char(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_body_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// True if `text` carries an unused-attribute annotation *written out* —
/// `__attribute__((unused))`, `__attribute__((__unused__))`,
/// `[[maybe_unused]]`, or the bare `__unused`/`__maybe_unused` spellings.
///
/// The attribute-syntax requirement is what makes this safe to run over a
/// whole declaration: `int unused;` declares a variable that happens to be
/// *named* `unused` and must still be reported, so a bare `unused` token
/// only counts inside `__attribute__(...)` or `[[...]]`.
pub fn has_unused_attribute(text: &str) -> bool {
    if (text.contains("__attribute__") || text.contains("[["))
        && mentions_unused_attribute_token(text)
    {
        return true;
    }
    // Reserved-identifier spellings need no surrounding syntax: `__unused`
    // cannot be a user's own variable name.
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if is_ident_start_char(chars[i]) {
            let start = i;
            while i < chars.len() && is_ident_body_char(chars[i]) {
                i += 1;
            }
            let tok: String = chars[start..i].iter().collect();
            if tok.starts_with("__") && UNUSED_ATTRIBUTE_TOKENS.contains(&tok.as_str()) {
                return true;
            }
        } else {
            i += 1;
        }
    }
    false
}

/// Collect every `#define NAME ...` whose replacement text *is* an
/// unused-attribute annotation (e.g. seL4's `#define UNUSED
/// __attribute__((unused))`). Plain regex over raw text like
/// `collect_packed_macro_names`, and deliberately independent of any single
/// file's declarations so it can be merged project-wide: the `#define`
/// almost always lives in a header far from the annotated declaration.
///
/// Resolving the macro's *body* is what keeps this name-independent — a
/// project spelling the macro `SEL4_UNUSED`, `MAYBE`, or anything else is
/// recognized, and a macro merely *named* `UNUSED` that expands to
/// something else is not.
pub fn collect_unused_attribute_macro_names(
    source: &str,
    out: &mut std::collections::HashSet<String>,
) {
    for cap in define_line_re().captures_iter(source) {
        let body = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        // A function-like macro (`#define UNUSED_PARAM(x) ...`) is not an
        // attribute annotation, so require the body to not open with `(`
        // immediately after the name.
        if body.starts_with('(') {
            continue;
        }
        if mentions_unused_attribute_token(body) {
            if let Some(name) = cap.get(1) {
                out.insert(name.as_str().to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse_c_code(code: &str) -> (tree_sitter::Tree, String) {
        let mut parser = Parser::new();
        let language = crate::parser::c_language();
        parser.set_language(&language).unwrap();
        let tree = parser.parse(code, None).unwrap();
        (tree, code.to_string())
    }

    #[test]
    fn test_get_node_text() {
        let (tree, source) = parse_c_code("int x = 5;");
        let root = tree.root_node();
        let text = get_node_text(&root, &source);
        assert_eq!(text, "int x = 5;");
    }

    #[test]
    fn test_find_containing_function() {
        let (tree, _source) = parse_c_code("void foo() { int x = 5; }");
        let root = tree.root_node();

        // Find the declaration node (int x = 5)
        let func_def = root.child(0).unwrap();
        assert_eq!(func_def.kind(), "function_definition");

        // Find a node inside the function
        let compound_stmt = func_def.child_by_field_name("body").unwrap();
        let decl = compound_stmt.child(1).unwrap(); // Skip opening brace

        let containing_func = find_containing_function(&decl);
        assert!(containing_func.is_some());
        assert_eq!(containing_func.unwrap().kind(), "function_definition");
    }

    #[test]
    fn test_find_array_size() {
        let text = "int main() { int arr[10]; }";
        let size = find_array_size("arr", text);
        assert_eq!(size, Some(10));
    }

    #[test]
    fn test_is_signed_type() {
        assert!(is_signed_type("int"));
        assert!(is_signed_type("signed int"));
        assert!(is_signed_type("int32_t"));
        assert!(!is_signed_type("unsigned int"));
        assert!(!is_signed_type("size_t"));
    }

    #[test]
    fn test_is_unsigned_type() {
        assert!(is_unsigned_type("unsigned int"));
        assert!(is_unsigned_type("size_t"));
        assert!(is_unsigned_type("uint32_t"));
        assert!(!is_unsigned_type("int"));
        assert!(!is_unsigned_type("signed int"));
    }

    #[test]
    fn test_get_type_size() {
        assert_eq!(get_type_size("char"), 1);
        assert_eq!(get_type_size("short"), 2);
        assert_eq!(get_type_size("int"), 4);
        assert_eq!(get_type_size("long"), 8);
        assert_eq!(get_type_size("int *"), 8);
    }

    /// `find_enclosing_declaration_for_identifier` must resolve a
    /// `for (int i = ...; ...) { ... }` loop variable's declaration for
    /// every occurrence within the for-statement (condition, update, and
    /// body) -- not just ones inside a nested `compound_statement`. The
    /// declaration is a direct child of `for_statement`, one level away
    /// from any `compound_statement`, which an earlier version of this
    /// function never looked at (an earlier fix regression, fixed alongside).
    #[test]
    fn test_find_enclosing_declaration_for_identifier_for_loop_var() {
        let (tree, source) =
            parse_c_code("void f(void) { for (int i = 0; i < 10; i++) { use(i); } }");
        let root = tree.root_node();
        let idents = query::find_descendants_of_kind(root, "identifier");
        let occurrences: Vec<_> = idents
            .iter()
            .filter(|n| get_node_text(n, &source) == "i")
            .collect();
        // declarator, condition, update, and the body's use(i) -- 4 total.
        assert_eq!(occurrences.len(), 4);
        let decl_node = occurrences[0];
        for occurrence in &occurrences[1..] {
            let resolved = find_enclosing_declaration_for_identifier(occurrence, "i", &source);
            assert!(
                resolved.is_some(),
                "expected occurrence at byte {} to resolve to the for-loop's own declaration",
                occurrence.start_byte()
            );
            let resolved = resolved.unwrap();
            assert!(resolved.start_byte() <= decl_node.start_byte());
            assert_eq!(resolved.kind(), "declaration");
        }
    }

    /// A shadowing re-declaration inside the loop body must still win over
    /// the for-loop's own declaration -- the widened for_statement search
    /// must not short-circuit the existing nearest-scope-wins behavior.
    #[test]
    fn test_find_enclosing_declaration_for_identifier_shadow_in_loop_body() {
        let (tree, source) =
            parse_c_code("void f(void) { for (int i = 0; i < 10; i++) { int i = 5; use(i); } }");
        let root = tree.root_node();
        let idents = query::find_descendants_of_kind(root, "identifier");
        let use_i = idents
            .iter()
            .rev()
            .find(|n| get_node_text(n, &source) == "i")
            .unwrap();
        let resolved = find_enclosing_declaration_for_identifier(use_i, "i", &source).unwrap();
        let inner_decl_text = get_node_text(&resolved, &source);
        assert!(
            inner_decl_text.contains("= 5"),
            "expected the inner shadowing declaration, got: {inner_decl_text}"
        );
    }

    /// A declaration written inside a `#ifdef`/`#endif` block has the same
    /// enclosing scope as one written directly -- textual inclusion, not a
    /// new C scope. A read anywhere else in that enclosing block (inside
    /// the same `#ifdef` branch, or after the `#endif` entirely) must still
    /// resolve back to it, not fail to resolve just because the
    /// declaration is nested one level inside a `preproc_ifdef` rather than
    /// being a direct child of the enclosing `compound_statement`.
    #[test]
    fn test_find_enclosing_declaration_for_identifier_inside_ifdef() {
        let (tree, source) = parse_c_code(
            "int f(int x) { \
             #ifdef NEED_AP_MLME\n\
             int color = x;\n\
             #endif\n\
             return color; }",
        );
        let root = tree.root_node();
        let idents = query::find_descendants_of_kind(root, "identifier");
        let use_color = idents
            .iter()
            .rev()
            .find(|n| get_node_text(n, &source) == "color")
            .unwrap();
        let resolved = find_enclosing_declaration_for_identifier(use_color, "color", &source);
        assert!(
            resolved.is_some(),
            "expected the ifdef-nested declaration to resolve"
        );
        assert_eq!(resolved.unwrap().kind(), "declaration");
    }
}

#[cfg(test)]
mod documented_precondition_tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse(code: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        parser.parse(code, None).unwrap()
    }

    #[test]
    fn prototype_under_attribute_macro_with_precondition() {
        let code = r#"
/**
 * \brief x
 * \param ctx    The context. It must point to a valid context.
 * \param mode   The mode.
 * \param key    The key. This must be a readable buffer of \p bits bits.
 * \param out    The output buffer.
 * \return 0
 */
MBEDTLS_CHECK_RETURN_TYPICAL
int f(struct c *ctx, int mode, const unsigned char *key, unsigned char *out);

/** \param p The pointer. */
int g(int *p);
"#;
        let tree = parse(code);
        let map = documented_nonnull_parameters(&tree.root_node(), code);
        assert_eq!(map.get("f"), Some(&vec![0, 2]));
        assert_eq!(map.get("g"), None);
    }

    #[test]
    fn param_blocks_end_at_the_next_command() {
        let blocks = doc_param_blocks(
            "/** \\param a The a. \\param[in] b Must not be \\c NULL. \\return 0 */",
        );
        assert_eq!(blocks.get("a").map(String::as_str), Some("The a."));
        assert!(states_nonnull(blocks.get("b").unwrap()));
        assert!(!states_nonnull(blocks.get("a").unwrap()));
    }
}

#[cfg(test)]
mod preproc_and_literal_position_tests {
    use super::{is_in_string_or_char_literal, is_on_preproc_directive_line};

    fn at(src: &str, needle: &str) -> usize {
        src.find(needle).expect("needle present in fixture")
    }

    #[test]
    fn directive_line_detected_and_body_is_not() {
        let src = "#if defined(X)\nint a = b / c;\n#endif\n";
        assert!(is_on_preproc_directive_line(src, at(src, "defined")));
        // The guarded body is ordinary runtime code.
        assert!(!is_on_preproc_directive_line(src, at(src, "b / c")));
    }

    #[test]
    fn directive_continuation_lines_follow_upward() {
        // Only the first physical line carries the `#`, but a rule can land on
        // any of them.
        let src = "#if defined(A) && \\\n    defined(B)\nint x;\n";
        assert!(is_on_preproc_directive_line(src, at(src, "defined(B)")));
        assert!(!is_on_preproc_directive_line(src, at(src, "int x")));
    }

    #[test]
    fn blank_line_does_not_borrow_a_later_hash() {
        // Trimming the rest of the file rather than this line would skip the
        // blank line and find the `#` below it.
        let src = "int a;\n\n#define B 1\n";
        assert!(!is_on_preproc_directive_line(src, at(src, "\n\n") + 1));
    }

    #[test]
    fn string_contents_are_not_code() {
        // The hostap shape: the `%` of a conversion specifier is inside a
        // literal, however the damaged tree parsed it.
        let src = "f(\"Line %d: Invalid bss_load_test\", line);\n";
        assert!(is_in_string_or_char_literal(src, at(src, "%d")));
        assert!(is_in_string_or_char_literal(src, at(src, "bss_load_test")));
    }

    #[test]
    fn real_operators_outside_literals_are_code() {
        let src = "printf(\"%d\", a % b);\n";
        assert!(is_in_string_or_char_literal(src, at(src, "%d")));
        // The modulo after the literal closes is genuine.
        assert!(!is_in_string_or_char_literal(src, at(src, "a % b") + 2));
    }

    #[test]
    fn apostrophe_in_comment_does_not_swallow_the_file() {
        // A naive scanner opens a char literal at "don't" and then reports
        // every later byte as being inside it.
        let src = "/* don't do this */\nint z = a % b;\n";
        assert!(!is_in_string_or_char_literal(src, at(src, "a % b") + 2));
    }

    #[test]
    fn escapes_and_nested_quotes_are_handled() {
        let src = "const char *s = \"it's \\\" tricky\";\nint z = a % b;\n";
        assert!(is_in_string_or_char_literal(src, at(src, "tricky")));
        assert!(!is_in_string_or_char_literal(src, at(src, "a % b") + 2));
    }

    #[test]
    fn char_literal_contents_are_not_code() {
        let src = "if (c == '%') { }\nint z = a % b;\n";
        assert!(is_in_string_or_char_literal(src, at(src, "'%'") + 1));
        assert!(!is_in_string_or_char_literal(src, at(src, "a % b") + 2));
    }
}

#[cfg(test)]
mod include_guard_tests {
    use super::is_include_guard;
    use tree_sitter::Parser;

    fn parse(code: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        parser.parse(code, None).unwrap()
    }

    /// The first `preproc_ifdef` at file scope.
    fn top_ifdef<'a>(tree: &'a tree_sitter::Tree) -> tree_sitter::Node<'a> {
        let root = tree.root_node();
        let mut cursor = root.walk();
        let found = root
            .named_children(&mut cursor)
            .find(|n| n.kind() == "preproc_ifdef");
        found.expect("fixture has a file-scope #ifdef/#ifndef")
    }

    #[test]
    fn guard_with_matching_define_first() {
        let src = "#ifndef LIST_H\n#define LIST_H\nstatic inline void f(int *p) { *p = 1; }\n#endif /* LIST_H */\n";
        let tree = parse(src);
        assert!(is_include_guard(&top_ifdef(&tree), src));
    }

    #[test]
    fn comment_before_the_define_is_allowed() {
        let src = "#ifndef LIST_H\n/* guard */\n#define LIST_H\nint x;\n#endif\n";
        let tree = parse(src);
        assert!(is_include_guard(&top_ifdef(&tree), src));
    }

    #[test]
    fn ifdef_is_not_a_guard() {
        let src = "#ifdef LIST_H\n#define LIST_H\nint x;\n#endif\n";
        let tree = parse(src);
        assert!(!is_include_guard(&top_ifdef(&tree), src));
    }

    #[test]
    fn different_name_is_not_a_guard() {
        // `#ifndef HAVE_FOO` / `#define foo(x) ...`: a fallback definition,
        // which is exactly the alternate-body shape the caller is cautious of.
        let src = "#ifndef HAVE_FOO\n#define foo(x) (x)\nint x;\n#endif\n";
        let tree = parse(src);
        assert!(!is_include_guard(&top_ifdef(&tree), src));
    }

    #[test]
    fn else_arm_is_not_a_guard() {
        let src = "#ifndef X\n#define X\nint a;\n#else\nint b;\n#endif\n";
        let tree = parse(src);
        assert!(!is_include_guard(&top_ifdef(&tree), src));
    }

    #[test]
    fn code_before_the_define_is_not_a_guard() {
        let src = "#ifndef X\nint a;\n#define X\n#endif\n";
        let tree = parse(src);
        assert!(!is_include_guard(&top_ifdef(&tree), src));
    }

    #[test]
    fn nested_guard_shape_is_not_a_guard() {
        // Same text one level down: not at file scope, so the tight
        // predicate declines and the caller keeps its caution.
        let src = "void f(void) {\n#ifndef X\n#define X\nint a;\n#endif\n}\n";
        let tree = parse(src);
        let root = tree.root_node();
        let nested = {
            fn find<'a>(n: tree_sitter::Node<'a>) -> Option<tree_sitter::Node<'a>> {
                if n.kind() == "preproc_ifdef" {
                    return Some(n);
                }
                let mut c = n.walk();
                let kids: Vec<_> = n.children(&mut c).collect();
                kids.into_iter().find_map(find)
            }
            find(root).expect("nested #ifndef parsed")
        };
        assert!(!is_include_guard(&nested, src));
    }
}
