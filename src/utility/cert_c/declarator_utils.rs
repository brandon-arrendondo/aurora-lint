// Declarator utilities for CERT C rules
// This module provides reusable functions for analyzing C declarators (arrays, pointers, function pointers)

use crate::utility::cert_c::node_children::NodeChildren;
use tree_sitter::Node;

// ============================================================================
// Declarator Type Checking
// ============================================================================

/// Check if a declarator contains a specific kind of declarator in its tree
/// This is the generic recursive function that powers all specific checks
///
/// # Arguments
/// * `node` - The declarator node to check
/// * `target_kind` - The kind of declarator to search for (e.g., "array_declarator", "pointer_declarator")
///
/// # Returns
/// `true` if the declarator tree contains a node of the target kind
///
/// # Examples
/// ```no_run
/// use aurora_lint::utility::cert_c::declarator_utils::has_declarator_of_kind;
/// use tree_sitter::Node;
/// // Check if field has array declarator:
/// // let declarator: Node = /* get from parsed AST */;
/// // if has_declarator_of_kind(&declarator, "array_declarator") {
/// //     // This is an array field
/// // }
/// ```
pub fn has_declarator_of_kind(node: &Node, target_kind: &str) -> bool {
    if node.kind() == target_kind {
        return true;
    }

    // Recursively check children
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if has_declarator_of_kind(&child, target_kind) {
                return true;
            }
        }
    }

    false
}

/// Check if a declarator is an array (has array_declarator)
///
/// # Examples
/// ```no_run
/// use aurora_lint::utility::cert_c::declarator_utils::is_array_declarator;
/// use tree_sitter::Node;
/// // int arr[10];      // returns true
/// // int *ptr;         // returns false
/// // int arr[5][10];   // returns true
/// ```
pub fn is_array_declarator(node: &Node) -> bool {
    has_declarator_of_kind(node, "array_declarator")
}

/// Check if a declarator is a pointer (has pointer_declarator)
///
/// # Examples
/// ```no_run
/// use aurora_lint::utility::cert_c::declarator_utils::is_pointer_declarator;
/// use tree_sitter::Node;
/// // int *ptr;         // returns true
/// // int **ptr;        // returns true
/// // int arr[10];      // returns false
/// ```
pub fn is_pointer_declarator(node: &Node) -> bool {
    has_declarator_of_kind(node, "pointer_declarator")
}

/// Check if a declarator is a function pointer (has function_declarator)
///
/// # Examples
/// ```no_run
/// use aurora_lint::utility::cert_c::declarator_utils::is_function_declarator;
/// use tree_sitter::Node;
/// // int (*fn)(int);   // returns true
/// // int *ptr;         // returns false
/// ```
pub fn is_function_declarator(node: &Node) -> bool {
    has_declarator_of_kind(node, "function_declarator")
}

// ============================================================================
// Typedef declarator chains
// ============================================================================

/// Whether a declarator declares a function (`f(void)`, `*f(void)`) rather
/// than an object, a function pointer (`(*fp)(void)`) included. The
/// derivation applied to the name itself decides: a function returning a
/// function pointer, `(*f(int))(void)`, is a function, and a pointer to a
/// function, `(*fp)(void)`, is an object. In a `typedef` the name is a
/// `type_identifier`, so the same test says whether the typedef names a
/// function type (`typedef int (handler)(void);`) or a pointer to one.
pub fn declares_function(declarator: &Node) -> bool {
    let mut d = *declarator;
    let mut nearest_name: Option<&str> = None;
    loop {
        match d.kind() {
            "identifier" | "type_identifier" => return nearest_name == Some("function_declarator"),
            "pointer_declarator" | "function_declarator" | "array_declarator" => {
                nearest_name = Some(d.kind())
            }
            "parenthesized_declarator" | "attributed_declarator" => {}
            _ => return false,
        }
        // `inner_declarator` does not step into a parenthesized typedef
        // name, `typedef int (handler)(void);`.
        let next = inner_declarator(&d).or_else(|| {
            let mut cursor = d.walk();
            let name = d
                .named_children(&mut cursor)
                .find(|c| c.kind() == "type_identifier");
            name
        });
        match next {
            Some(inner) if inner.id() != d.id() => d = inner,
            _ => return false,
        }
    }
}

/// The `pointer_declarator` that makes the declared object a pointer, or
/// `None` when the object's own type comes from the declaration's specifiers.
/// The derivation nearest the name decides, as in [`declares_function`]; an
/// array is seen through, because an array's elements carry its qualifiers.
/// So the qualifiers that apply to the object itself are this node's
/// `type_qualifier` children: `int *volatile p` (Some, volatile),
/// `volatile int *p` (Some, unqualified: only the pointee is volatile),
/// `int *volatile a[4]` (Some, volatile elements), `volatile int x` (None).
pub fn object_pointer_declarator<'a>(declarator: &Node<'a>) -> Option<Node<'a>> {
    let mut d = *declarator;
    let mut nearest: Option<Node<'a>> = None;
    loop {
        match d.kind() {
            "identifier" => return nearest.filter(|n| n.kind() == "pointer_declarator"),
            "pointer_declarator" | "function_declarator" => nearest = Some(d),
            "array_declarator" | "parenthesized_declarator" | "attributed_declarator" => {}
            _ => return None,
        }
        match inner_declarator(&d) {
            Some(inner) if inner.id() != d.id() => d = inner,
            _ => return None,
        }
    }
}

/// Whether the object `declarator` declares is itself `const`, `decl` being
/// the `declaration` (or `type_definition`) it belongs to: a `const` on the
/// pointer nearest the name (`char *const p`), or, when the object's type
/// comes from the specifiers, a `const` among them (`static const int t[4]`,
/// `int const k`, an array's elements carrying its qualifier) or a typedef
/// in scope that names a const type (`typedef const int cint; cint k;`).
/// Constness belongs to each declarator: `const char *s` is a writable
/// pointer, and `static const int k = 1, *p;` declares one const object and
/// one writable pointer. A function, or a typedef this file does not define
/// (a header's), is not known to be const.
pub fn declares_const_object(decl: &Node, declarator: &Node, source: &str) -> bool {
    qualified_object_within(decl, declarator, source, "const", 8)
}

/// Whether the object `declarator` declares is itself `_Atomic`, read as
/// [`declares_const_object`] reads `const`: `_Atomic int n`, `_Atomic(int) n`,
/// `int *_Atomic p`, `static _Atomic struct s v`, a typedef in scope that
/// names an atomic type, and a `<stdatomic.h>` name such as `atomic_int` when
/// no typedef of that name is in scope and the file includes `<stdatomic.h>`
/// before it ([`includes_system_header_before`]). An array's elements carry
/// its qualifier, so `_Atomic int c[8]` is atomic, and a member declarator
/// of a `field_declaration` is read the same way. `_Atomic int *p` is a
/// plain pointer to an atomic object ([`declares_pointer_to_atomic`]).
pub fn declares_atomic_object(decl: &Node, declarator: &Node, source: &str) -> bool {
    qualified_object_within(decl, declarator, source, "_Atomic", 8)
}

/// Whether `declarator` declares a plain pointer (`*p`, one level, no array
/// or function between) to an `_Atomic` object, read from the specifiers as
/// [`declares_atomic_object`] reads them: `_Atomic int *p`, `atomic_int *p`.
pub fn declares_pointer_to_atomic(decl: &Node, declarator: &Node, source: &str) -> bool {
    let mut d = *declarator;
    while matches!(
        d.kind(),
        "parenthesized_declarator" | "attributed_declarator"
    ) {
        match inner_declarator(&d) {
            Some(inner) if inner.id() != d.id() => d = inner,
            _ => return false,
        }
    }
    if d.kind() != "pointer_declarator" {
        return false;
    }
    let mut name = d.child_by_field_name("declarator");
    while let Some(n) = name.filter(|n| n.kind() == "parenthesized_declarator") {
        name = inner_declarator(&n).filter(|inner| inner.id() != n.id());
    }
    name.is_some_and(|n| n.kind() == "identifier")
        && specifiers_qualified(decl, source, "_Atomic", 8)
}

/// The definitions, with a body, of the structure or union type that
/// `decl`'s specifiers name, `decl` being a `declaration`, `field_declaration`
/// or `type_definition`: the specifier itself when it has a body
/// (`static struct { int n; } g;`), the definitions of its tag that are
/// visible at `decl` ([`record_definitions_in_scope`]), or those of the
/// typedef in scope that the type names, followed to its own specifiers.
/// The declarator's derivations are not read: a caller that needs the
/// element type of an array, or rules out a pointer, checks them itself.
/// Empty when no definition is in this file, as for a type a header
/// defines.
pub fn record_definitions_of<'a>(decl: &Node<'a>, source: &str) -> Vec<Node<'a>> {
    let mut decl = *decl;
    for _ in 0..8 {
        let Some(ty) = decl.child_by_field_name("type") else {
            return Vec::new();
        };
        match ty.kind() {
            "struct_specifier" | "union_specifier" => {
                if ty.child_by_field_name("body").is_some() {
                    return vec![ty];
                }
                let Some(tag) = ty.child_by_field_name("name") else {
                    return Vec::new();
                };
                return record_definitions_in_scope(
                    &ty,
                    ty.kind(),
                    &source[tag.byte_range()],
                    source,
                );
            }
            "type_identifier" => {
                let name = &source[ty.byte_range()];
                let Some(typedef) = crate::utility::cert_c::ast_utils::typedef_definition_in_scope(
                    &ty, name, source,
                ) else {
                    return Vec::new();
                };
                decl = typedef;
            }
            _ => return Vec::new(),
        }
    }
    Vec::new()
}

/// The definitions, with a body, of the `kind` (`struct_specifier` or
/// `union_specifier`) tagged `tag` that are visible at `site`: those in the
/// innermost scope enclosing `site` that defines the tag before it, a block
/// or the file. A tag defined inside another structure's body belongs to the
/// scope around that structure (C11 6.2.1p4). Several are returned when the
/// file defines the tag more than once in that scope, as in the arms of an
/// `#if`; a caller that removes a finding should require all of them to
/// agree. A definition in an `#if 0` arm, or in an arm other than the one
/// `site` is in, is not visible. When a definition sits in a conditional
/// before `site` whose arms that can be taken do not all define the tag (one
/// leaves it to a header, or there is no `#else`), which definition applies
/// is not known and nothing is returned. A bodiless `struct S;` in an inner
/// block that redeclares the tag is not read.
pub fn record_definitions_in_scope<'a>(
    site: &Node<'a>,
    kind: &str,
    tag: &str,
    source: &str,
) -> Vec<Node<'a>> {
    let mut root = *site;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let encloses_site = |scope: &Node| {
        scope.start_byte() <= site.start_byte() && site.end_byte() <= scope.end_byte()
    };
    // Each visible definition, with the start of the block it is in (0 for
    // the file): the innermost such block encloses the others
    let mut visible: Vec<(usize, Node<'a>)> = Vec::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if n.start_byte() >= site.start_byte() {
            continue;
        }
        let defines_tag = n.kind() == kind
            && n.child_by_field_name("body").is_some()
            && n.child_by_field_name("name")
                .is_some_and(|t| &source[t.byte_range()] == tag);
        if defines_tag {
            let block = std::iter::successors(n.parent(), Node::parent)
                .find(|p| p.kind() == "compound_statement");
            match block {
                None => visible.push((0, n)),
                Some(b) if encloses_site(&b) => visible.push((b.start_byte() + 1, n)),
                Some(_) => {}
            }
        }
        // A definition in a block not enclosing `site` is not visible there
        let opens_block = matches!(n.kind(), "compound_statement" | "function_definition");
        if !opens_block || encloses_site(&n) {
            let mut cursor = n.walk();
            stack.extend(n.named_children(&mut cursor));
        }
    }
    let Some(innermost) = visible.iter().map(|(scope, _)| *scope).max() else {
        return Vec::new();
    };
    let mut found: Vec<Node<'a>> = visible
        .into_iter()
        .filter(|(scope, _)| *scope == innermost)
        .map(|(_, n)| n)
        .collect();
    found.sort_by_key(Node::start_byte);
    // A definition in a preprocessor arm is in effect at `site` only in the
    // arm `site` is in, or, for a conditional `site` follows, when every arm
    // that can be taken defines the tag too: an arm that leaves it to a
    // header, or no `#else`, gives it a meaning this file does not show
    let mut kept = Vec::new();
    for definition in &found {
        match arms_admit(definition, site, source, &|arm| {
            found.iter().any(|d| in_arm_body(d, arm))
        }) {
            Some(true) => kept.push(*definition),
            Some(false) => {}
            None => return Vec::new(),
        }
    }
    kept
}

/// The preprocessor conditional kinds that open a conditional, and every
/// kind of arm in one.
const CONDITIONALS: &[&str] = &["preproc_if", "preproc_ifdef"];
const CONDITIONAL_ARMS: &[&str] = &[
    "preproc_if",
    "preproc_ifdef",
    "preproc_elif",
    "preproc_elifdef",
    "preproc_else",
];

/// The arms of the conditional that opens with `conditional`, in order, each
/// with whether it can never be part of a translation unit that compiles,
/// and whether one of them is taken whatever is defined.
///
/// An arm is never taken when its condition is the constant `0`, when an
/// earlier arm's condition is the constant `1`, or when its body holds an
/// `#error` directive, which stops any translation that takes it. One arm is
/// always taken when the last is an `#else` or an arm's condition is `1`.
fn conditional_arms<'a>(conditional: &Node<'a>, source: &str) -> (Vec<(Node<'a>, bool)>, bool) {
    let mut arms = Vec::new();
    let mut covered = false;
    let mut arm = Some(*conditional);
    while let Some(a) = arm {
        let condition = a
            .child_by_field_name("condition")
            .map(|c| constant_condition(&source[c.byte_range()]));
        let never = covered || condition == Some(Some(false)) || arm_body_errors(&a, source);
        covered = covered || a.kind() == "preproc_else" || condition == Some(Some(true));
        arms.push((a, never));
        arm = a.child_by_field_name("alternative");
    }
    (arms, covered)
}

/// The value of an `#if` condition that is the constant `0` or `1`, possibly
/// parenthesized; `None` for any other condition.
fn constant_condition(text: &str) -> Option<bool> {
    let mut t = text.trim();
    while let Some(inner) = t.strip_prefix('(').and_then(|s| s.strip_suffix(')')) {
        t = inner.trim();
    }
    match t {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

/// Whether `arm` itself, outside any conditional nested in it, holds an
/// `#error` directive.
fn arm_body_errors(arm: &Node, source: &str) -> bool {
    arm_body(arm).iter().any(|n| {
        n.kind() == "preproc_call"
            && n.child_by_field_name("directive").is_some_and(|d| {
                let d = &source[d.byte_range()];
                d.strip_prefix('#')
                    .is_some_and(|r| r.trim_start() == "error")
            })
    })
}

/// The nodes an arm holds: its children other than its condition (or
/// `#ifdef` name) and the arm after it.
fn arm_body<'a>(arm: &Node<'a>) -> Vec<Node<'a>> {
    let skip: Vec<usize> = ["condition", "name", "alternative"]
        .iter()
        .filter_map(|f| arm.child_by_field_name(f))
        .map(|n| n.id())
        .collect();
    let mut cursor = arm.walk();
    let body: Vec<Node<'a>> = arm
        .named_children(&mut cursor)
        .filter(|c| !skip.contains(&c.id()))
        .collect();
    body
}

fn encloses(outer: &Node, inner: &Node) -> bool {
    outer.start_byte() <= inner.start_byte() && inner.end_byte() <= outer.end_byte()
}

/// Whether `n` is in `arm` itself rather than in a later arm of the same
/// conditional.
fn in_arm_body(n: &Node, arm: &Node) -> bool {
    encloses(arm, n)
        && arm
            .child_by_field_name("alternative")
            .is_none_or(|alt| !encloses(&alt, n))
}

/// Whether the preprocessor arms around `n` leave it in effect at `site`.
/// For each conditional arm `n` is in, out to the file: an arm that is never
/// taken (`#if 0`, or one that stops at `#error`) is never in effect
/// (`Some(false)`); an arm of a conditional that holds `site` is in effect
/// only when it is `site`'s own arm (`Some(false)` otherwise); and for a
/// conditional before `site`, `proves` must hold of every arm that can be
/// taken, with one of them always taken (an `#else` or `#if 1`), or which arm
/// is taken decides the answer and it is not known (`None`).
fn arms_admit(n: &Node, site: &Node, source: &str, proves: &dyn Fn(&Node) -> bool) -> Option<bool> {
    let mut child = *n;
    while let Some(parent) = child.parent() {
        let entered_arm = CONDITIONAL_ARMS.contains(&parent.kind())
            && parent.child_by_field_name("alternative") != Some(child);
        if entered_arm {
            let arm = parent;
            let mut conditional = arm;
            while let Some(up) = conditional.parent() {
                if CONDITIONAL_ARMS.contains(&up.kind())
                    && up.child_by_field_name("alternative") == Some(conditional)
                {
                    conditional = up;
                } else {
                    break;
                }
            }
            let (arms, one_taken) = conditional_arms(&conditional, source);
            if arms.iter().any(|(a, never)| *never && a.id() == arm.id()) {
                return Some(false);
            }
            if encloses(&conditional, site) {
                if !in_arm_body(site, &arm) {
                    return Some(false);
                }
            } else {
                let live: Vec<&Node> = arms
                    .iter()
                    .filter(|(_, never)| !never)
                    .map(|(a, _)| a)
                    .collect();
                if !one_taken || !live.iter().all(|a| proves(a)) {
                    return None;
                }
            }
        }
        child = parent;
    }
    Some(true)
}

/// The declarations of the member `field` of the structure or union
/// definition `record` (a `struct_specifier` or `union_specifier` with a
/// body), each as its `field_declaration` and the declarator naming it,
/// including one inside an `#if` arm and one reached through an anonymous
/// structure or union member (C11 6.7.2.1p13), unless that member is
/// `_Atomic`. Several when the arms of an `#if` each declare it.
pub fn member_declarations<'a>(
    record: &Node<'a>,
    field: &str,
    source: &str,
) -> Vec<(Node<'a>, Node<'a>)> {
    let mut found = Vec::new();
    let Some(body) = record.child_by_field_name("body") else {
        return found;
    };
    let mut stack = vec![body];
    while let Some(n) = stack.pop() {
        let mut cursor = n.walk();
        for child in n.named_children(&mut cursor) {
            match child.kind() {
                "field_declaration" => {
                    let mut dc = child.walk();
                    let declarators: Vec<Node<'a>> = child
                        .children_by_field_name("declarator", &mut dc)
                        .collect();
                    if declarators.is_empty() {
                        // An anonymous structure or union member
                        // An `_Atomic` one is an atomic structure, whose
                        // members are not atomic on their own (C11
                        // 6.5.2.3p5), so they are not returned
                        if let Some(inner) = child.child_by_field_name("type").filter(|t| {
                            matches!(t.kind(), "struct_specifier" | "union_specifier")
                                && t.child_by_field_name("name").is_none()
                                && !has_type_qualifier(&child, "_Atomic")
                        }) {
                            found.extend(member_declarations(&inner, field, source));
                        }
                    }
                    for d in declarators {
                        if member_name(&d).is_some_and(|n| &source[n.byte_range()] == field) {
                            found.push((child, d));
                        }
                    }
                }
                k if k.starts_with("preproc_") => stack.push(child),
                _ => {}
            }
        }
    }
    found
}

/// The `field_identifier` a member declarator declares, through pointer,
/// array, parenthesized and attributed declarators. `None` for a bit-field
/// without a name and for a shape this does not read.
fn member_name<'a>(declarator: &Node<'a>) -> Option<Node<'a>> {
    let mut d = *declarator;
    for _ in 0..16 {
        if d.kind() == "field_identifier" {
            return Some(d);
        }
        let next = d.child_by_field_name("declarator").or_else(|| {
            let mut cursor = d.walk();
            let inner = d
                .named_children(&mut cursor)
                .find(|c| c.kind().ends_with("declarator") || c.kind() == "field_identifier");
            inner
        })?;
        if next.id() == d.id() {
            return None;
        }
        d = next;
    }
    None
}

fn qualified_object_within(
    decl: &Node,
    declarator: &Node,
    source: &str,
    qualifier: &str,
    depth: usize,
) -> bool {
    if depth == 0 || declares_function(declarator) {
        return false;
    }
    match nearest_pointer_derivation(declarator) {
        Some(Some(pointer)) => return has_type_qualifier(&pointer, qualifier),
        // A chain this does not read may hide a pointer: not known qualified
        None => return false,
        Some(None) => {}
    }
    specifiers_qualified(decl, source, qualifier, depth)
}

/// Whether the type `decl`'s specifiers name carries `qualifier`: among the
/// specifiers themselves, or through the typedef in scope they name.
fn specifiers_qualified(decl: &Node, source: &str, qualifier: &str, depth: usize) -> bool {
    if has_type_qualifier(decl, qualifier) {
        return true;
    }
    let Some(type_name) = decl
        .child_by_field_name("type")
        .filter(|t| t.kind() == "type_identifier")
    else {
        return false;
    };
    let name = &source[type_name.byte_range()];
    let Some(typedef) =
        crate::utility::cert_c::ast_utils::typedef_definition_in_scope(&type_name, name, source)
    else {
        return qualifier == "_Atomic"
            && is_stdatomic_type_name(name)
            && includes_system_header_before(&type_name, "stdatomic.h", source);
    };
    typedef_declarators(&typedef)
        .into_iter()
        .find(|d| TypedefShape::of(d, source).name.as_deref() == Some(name))
        .is_some_and(|d| qualified_object_within(&typedef, &d, source, qualifier, depth - 1))
}

/// Whether the file includes the system header `header` (`#include
/// <stdatomic.h>`) before `site`, whichever preprocessor arms are taken: at
/// file scope, in the arm of a conditional that `site` itself is in, or in
/// every arm that can be taken of a conditional with an `#else` (an `#if 0`
/// arm is never taken and needs no include). An include in only one arm of
/// `#if defined(__STDC_NO_ATOMICS__) ... #else ... #endif`, or in an arm
/// with no `#else`, is not in effect everywhere, so it does not count. The
/// library's names mean what the standard says only where its header is in
/// effect; a project's own compatibility header of the same names is not
/// the library. A header the file reaches only through another header is
/// not seen, so a caller that removes a finding on this answer stays
/// conservative.
pub fn includes_system_header_before(site: &Node, header: &str, source: &str) -> bool {
    let mut root = *site;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let mut cursor = root.walk();
    let top: Vec<Node> = root.named_children(&mut cursor).collect();
    included_in(&top, site, header, source)
}

/// Whether the directives `nodes`, in file order, include `<header>` before
/// `site` whichever arms are taken: [`includes_system_header_before`].
fn included_in(nodes: &[Node], site: &Node, header: &str, source: &str) -> bool {
    for node in nodes {
        if node.start_byte() >= site.start_byte() {
            break;
        }
        if node.kind() == "preproc_include" {
            let names = node.child_by_field_name("path").is_some_and(|p| {
                p.kind() == "system_lib_string"
                    && source[p.byte_range()]
                        .trim_start_matches('<')
                        .trim_end_matches('>')
                        .trim()
                        == header
            });
            if names {
                return true;
            }
        } else if CONDITIONALS.contains(&node.kind()) {
            let (arms, one_taken) = conditional_arms(node, source);
            if encloses(node, site) {
                // Only the arm `site` is in is taken where `site` is
                return arms.iter().any(|(arm, never)| {
                    !never
                        && in_arm_body(site, arm)
                        && included_in(&arm_body(arm), site, header, source)
                });
            }
            let mut live = arms.iter().filter(|(_, never)| !never).peekable();
            if one_taken
                && live.peek().is_some()
                && live.all(|(arm, _)| included_in(&arm_body(arm), site, header, source))
            {
                return true;
            }
        }
    }
    false
}

/// Whether `name` is one of the atomic integer type names `<stdatomic.h>`
/// defines (C11 7.17.6, C23 adds `atomic_char8_t`). `atomic_flag` is not one:
/// it is a structure with no arithmetic.
fn is_stdatomic_type_name(name: &str) -> bool {
    const NAMES: &[&str] = &[
        "atomic_bool",
        "atomic_char",
        "atomic_schar",
        "atomic_uchar",
        "atomic_short",
        "atomic_ushort",
        "atomic_int",
        "atomic_uint",
        "atomic_long",
        "atomic_ulong",
        "atomic_llong",
        "atomic_ullong",
        "atomic_char8_t",
        "atomic_char16_t",
        "atomic_char32_t",
        "atomic_wchar_t",
        "atomic_intptr_t",
        "atomic_uintptr_t",
        "atomic_size_t",
        "atomic_ptrdiff_t",
        "atomic_intmax_t",
        "atomic_uintmax_t",
    ];
    if NAMES.contains(&name) {
        return true;
    }
    // atomic_int_least8_t .. atomic_uint_fast64_t
    let Some(rest) = name
        .strip_prefix("atomic_uint_")
        .or_else(|| name.strip_prefix("atomic_int_"))
    else {
        return false;
    };
    let Some(width) = rest
        .strip_prefix("least")
        .or_else(|| rest.strip_prefix("fast"))
        .and_then(|w| w.strip_suffix("_t"))
    else {
        return false;
    };
    matches!(width, "8" | "16" | "32" | "64")
}

/// [`object_pointer_declarator`] for a declarator chain ending in either an
/// object's `identifier` or a typedef's `type_identifier`: `Some(None)` when
/// the name is reached with no pointer nearer it, so the specifiers give the
/// type, and `None` when the chain holds something this does not read.
fn nearest_pointer_derivation<'a>(declarator: &Node<'a>) -> Option<Option<Node<'a>>> {
    let mut d = *declarator;
    let mut nearest: Option<Node<'a>> = None;
    loop {
        match d.kind() {
            "identifier" | "type_identifier" | "field_identifier" => {
                return Some(nearest.filter(|n| n.kind() == "pointer_declarator"))
            }
            "pointer_declarator" | "function_declarator" => nearest = Some(d),
            "array_declarator" | "parenthesized_declarator" | "attributed_declarator" => {}
            _ => return None,
        }
        match inner_declarator(&d) {
            Some(inner) if inner.id() != d.id() => d = inner,
            _ => return None,
        }
    }
}

/// Whether `id` is the name a declaration declares rather than a use of a
/// name: the identifier at the end of a declarator chain of a `declaration`,
/// `parameter_declaration`, `field_declaration`, `type_definition` or
/// `function_definition`, in any of its declarators. An initializer and an
/// array size are uses.
pub fn is_declared_name(id: &Node) -> bool {
    let mut child = *id;
    while let Some(parent) = child.parent() {
        match parent.kind() {
            "pointer_declarator"
            | "array_declarator"
            | "function_declarator"
            | "parenthesized_declarator"
            | "attributed_declarator" => {
                if inner_declarator(&parent).is_none_or(|d| d.id() != child.id()) {
                    return false;
                }
            }
            "init_declarator" => {
                if parent
                    .child_by_field_name("declarator")
                    .is_none_or(|d| d.id() != child.id())
                {
                    return false;
                }
            }
            "declaration"
            | "parameter_declaration"
            | "field_declaration"
            | "type_definition"
            | "function_definition" => {
                let mut cursor = parent.walk();
                let found = parent
                    .children_by_field_name("declarator", &mut cursor)
                    .any(|d| d.id() == child.id());
                return found;
            }
            _ => return false,
        }
        child = parent;
    }
    false
}

/// The declarator one level inside `n`. Pointer, array and function
/// declarators name it as the `declarator` field; a parenthesized declarator
/// has no field for it (`( declarator )`, possibly with an `ms_call_modifier`
/// first), so fall back to the first named child that is a declarator.
pub fn inner_declarator<'a>(n: &Node<'a>) -> Option<Node<'a>> {
    if let Some(d) = n.child_by_field_name("declarator") {
        return Some(d);
    }
    let mut cursor = n.walk();
    let found = n
        .named_children(&mut cursor)
        .find(|c| c.kind().ends_with("declarator") || c.kind() == "identifier");
    found
}

/// The declarators a `type_definition` binds: one per name, so
/// `typedef struct tagPOINT { ... } POINT, *LPPOINT;` yields both, and only
/// `*LPPOINT` is a pointer.
pub fn typedef_declarators<'a>(n: &Node<'a>) -> Vec<Node<'a>> {
    let mut cursor = n.walk();
    let found: Vec<Node<'a>> = n
        .children_by_field_name("declarator", &mut cursor)
        .collect();
    found
}

/// Does the typedef's specifier list carry `const` (the pointee is const)?
/// Only direct children count: a `const` inside a struct body or a parameter
/// list qualifies something else.
pub fn typedef_has_const_qualifier(n: &Node) -> bool {
    has_type_qualifier(n, "const")
}

/// Whether `n`'s own `type_qualifier` children include `qualifier` (`const`,
/// `volatile`, `_Atomic`, ...), not one nested in a struct body or a
/// parameter list.
fn has_type_qualifier(n: &Node, qualifier: &str) -> bool {
    let mut cursor = n.walk();
    let found = n.named_children(&mut cursor).any(|c| {
        c.kind() == "type_qualifier" && {
            let mut inner = c.walk();
            let has = c.children(&mut inner).any(|k| k.kind() == qualifier);
            has
        }
    });
    found
}

/// What one typedef declarator chain spells, read from the outside in. Only
/// the chain is read -- never a struct body, whose pointer MEMBERS say nothing
/// about the type being named.
pub struct TypedefShape {
    /// The chain contains a `pointer_declarator`.
    pub is_pointer: bool,
    /// The chain contains a `function_declarator`: a function or function
    /// pointer type, which DCL05-C exempts.
    pub is_function: bool,
    /// The `type_identifier` at the end of the chain -- the name defined.
    pub name: Option<String>,
}

impl TypedefShape {
    /// Classify one declarator chain, starting at a `type_definition`'s
    /// `declarator` field.
    pub fn of(declarator: &Node, source: &str) -> Self {
        let mut shape = TypedefShape {
            is_pointer: false,
            is_function: false,
            name: None,
        };
        let mut cur = *declarator;
        loop {
            match cur.kind() {
                "pointer_declarator" => shape.is_pointer = true,
                "function_declarator" => shape.is_function = true,
                "type_identifier" | "identifier" => {
                    shape.name = Some(source[cur.byte_range()].to_string());
                    return shape;
                }
                _ => {}
            }
            match inner_declarator(&cur) {
                Some(next) => cur = next,
                None => return shape,
            }
        }
    }
}

/// Whether the parser swallowed the head of this `type_definition` into an
/// ERROR, so that its `type` and `declarator` fields are not the typedef's
/// at all. In miniaudio's
/// `typedef LONG (WINAPI * PFN)(HKEY hKey, const char* lpSubKey, DWORD ulOptions, DWORD samDesired, ...);`
/// the unknown `WINAPI` sends the parse into recovery, which takes
/// everything up to `hKey,` as an ERROR and ends the typedef at an invented
/// `;`, leaving `typedef const char *lpSubKey, ulOptions, DWORD`: read as
/// written, that makes `DWORD` a name for `char`.
///
/// Only an ERROR before the `type` field counts. A repair after the type
/// leaves it as written: seL4's
/// `typedef seL4_CapRights_t seL4_CapRights SEL4_DEPRECATED("...");` needs
/// a repair only after its name, and still binds that name correctly, so it
/// is no reason to drop the fact.
pub fn typedef_head_was_swallowed(type_definition: &Node) -> bool {
    let Some(ty) = type_definition.child_by_field_name("type") else {
        return false;
    };
    type_definition
        .child_nodes()
        .take_while(|c| c.id() != ty.id())
        .any(|c| c.is_error())
}

/// The names a `type_definition` binds to a pointer type in DCL05-C's sense:
/// a pointer somewhere in the declarator chain, not a function pointer (CERT
/// exempts those), and not a pointer to const (`typedef const POINT
/// *LPCPOINT`, where `const` already sits on the pointee). Shared by the
/// rule, which flags such a typedef where it is written, and the prescan,
/// which records the names cross-file so `const LPPOINT pt` in another file
/// can be recognised for what it is. A typedef with an ERROR
/// among its own children (a calling-convention macro left unresolved) is
/// skipped; an ERROR inside a struct body is not held against the name.
pub fn pointer_typedef_names_in(type_definition: &Node, source: &str) -> Vec<String> {
    let mut cursor = type_definition.walk();
    let broken = type_definition.children(&mut cursor).any(|c| c.is_error());
    if broken || typedef_has_const_qualifier(type_definition) {
        return Vec::new();
    }
    typedef_declarators(type_definition)
        .into_iter()
        .filter(|d| !d.has_error())
        .map(|d| TypedefShape::of(&d, source))
        .filter(|shape| shape.is_pointer && !shape.is_function)
        .filter_map(|shape| shape.name)
        .collect()
}

/// Every name a `type_definition` declares, whatever its shape:
/// `typedef struct tagPOINT { ... } POINT, *LPPOINT;` yields both.
pub fn typedef_names_in(type_definition: &Node, source: &str) -> Vec<String> {
    typedef_declarators(type_definition)
        .into_iter()
        .filter_map(|d| TypedefShape::of(&d, source).name)
        .collect()
}

/// Every name a file-scope `typedef` in `root` declares, outside the
/// regions `dead_code_ranges` proves no build compiles. A typedef in a
/// function body is that block's alone, so the walk does not enter one.
pub fn typedef_names_declared(root: &Node, source: &str) -> std::collections::HashSet<String> {
    let mut definitions = Vec::new();
    let mut stack = vec![*root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "type_definition" => definitions.push(node),
            "function_definition" | "compound_statement" => {}
            _ => {
                let mut cursor = node.walk();
                stack.extend(node.named_children(&mut cursor));
            }
        }
    }
    if definitions.is_empty() {
        return Default::default();
    }
    let dead = lang_parsing_substrate::dead_code_ranges(source);
    definitions
        .into_iter()
        .filter(|d| {
            let line = d.start_position().row + 1;
            !dead
                .iter()
                .any(|r| line >= r.start_line && line <= r.end_line)
        })
        .flat_map(|d| typedef_names_in(&d, source))
        .collect()
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

    fn find_declarator<'a>(tree: &'a tree_sitter::Tree) -> Option<Node<'a>> {
        let root = tree.root_node();
        // Find first declarator in the tree
        for i in 0..root.child_count() {
            if let Some(child) = root.child(i) {
                if child.kind() == "declaration" {
                    if let Some(declarator) = child.child_by_field_name("declarator") {
                        return Some(declarator);
                    }
                }
            }
        }
        None
    }

    #[test]
    fn test_is_array_declarator() {
        let tree = parse_c_code("int arr[10];");
        let declarator = find_declarator(&tree).unwrap();
        assert!(is_array_declarator(&declarator));
    }

    #[test]
    fn test_is_pointer_declarator() {
        let tree = parse_c_code("int *ptr;");
        let declarator = find_declarator(&tree).unwrap();
        assert!(is_pointer_declarator(&declarator));
    }

    #[test]
    fn test_is_not_array() {
        let tree = parse_c_code("int *ptr;");
        let declarator = find_declarator(&tree).unwrap();
        assert!(!is_array_declarator(&declarator));
    }

    #[test]
    fn test_is_not_pointer() {
        let tree = parse_c_code("int arr[10];");
        let declarator = find_declarator(&tree).unwrap();
        assert!(!is_pointer_declarator(&declarator));
    }

    #[test]
    fn test_multidimensional_array() {
        let tree = parse_c_code("int arr[5][10];");
        let declarator = find_declarator(&tree).unwrap();
        assert!(is_array_declarator(&declarator));
    }

    #[test]
    fn test_double_pointer() {
        let tree = parse_c_code("int **ptr;");
        let declarator = find_declarator(&tree).unwrap();
        assert!(is_pointer_declarator(&declarator));
    }

    /// Whether the object `code` declares is itself volatile, per
    /// `object_pointer_declarator` (or the specifiers when it says None).
    fn object_is_volatile(code: &str) -> bool {
        let tree = parse_c_code(code);
        let declarator = find_declarator(&tree).unwrap();
        let has_volatile = |n: &Node| {
            let mut cursor = n.walk();
            let found = n
                .children(&mut cursor)
                .any(|c| c.kind() == "type_qualifier" && &code[c.byte_range()] == "volatile");
            found
        };
        match object_pointer_declarator(&declarator) {
            Some(ptr) => has_volatile(&ptr),
            None => has_volatile(&declarator.parent().unwrap()),
        }
    }

    #[test]
    fn object_qualifiers_are_the_ones_nearest_the_name() {
        assert!(object_is_volatile("int *volatile p;"));
        assert!(!object_is_volatile("volatile int *p;"));
        assert!(object_is_volatile("volatile int x;"));
        assert!(object_is_volatile("int *volatile a[4];"));
        assert!(!object_is_volatile("int *volatile *pp;"));
        assert!(!object_is_volatile("int *volatile (*pa)[4];"));
    }

    #[test]
    fn declared_names_are_not_uses() {
        let code = "int n = 4; void f(int k) { int a[n], *b = &a[0], c = k; }";
        let tree = parse_c_code(code);
        let mut declared = Vec::new();
        let mut used = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(n) = stack.pop() {
            if n.kind() == "identifier" {
                let name = &code[n.byte_range()];
                if is_declared_name(&n) {
                    declared.push(name);
                } else {
                    used.push(name);
                }
            }
            let mut cursor = n.walk();
            stack.extend(n.children(&mut cursor));
        }
        declared.sort();
        used.sort();
        assert_eq!(declared, ["a", "b", "c", "f", "k", "n"]);
        assert_eq!(used, ["a", "k", "n"]);
    }
}
