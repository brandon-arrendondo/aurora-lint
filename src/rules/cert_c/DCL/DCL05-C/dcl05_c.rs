// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! DCL05-C: Use typedefs of non-pointer types only
//!
//! This rule detects typedefs that define pointer types, which can lead to
//! confusion about const-qualification and make code harder to understand.
//!
//! Violations:
//! - typedef int *IntPtr;  // typedef of a pointer type
//!
//! Compliant:
//! - typedef int Integer;  // typedef of non-pointer type
//! - Integer *ptr;         // pointer declared explicitly
//!
//! References:
//! - https://wiki.sei.cmu.edu/confluence/display/c/DCL05-C.+Use+typedefs+of+non-pointer+types+only

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::declarator_utils::{inner_declarator, pointer_typedef_names_in};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::Arc;
use tree_sitter::Node;

/// Win32 typedefs that are `T *` with no const on the pointee, from
/// `<windef.h>`/`<winnt.h>`, which a scan almost never has on its include
/// path. Facts about a named API, not a naming pattern: `LPCSTR` and the
/// other `LPC*`/`PC*` spellings are pointer-to-const and so belong to the
/// compliant side of the wiki's Windows example, and are left out.
const WIN32_POINTER_TYPEDEFS: &[&str] = &[
    "LPSTR", "LPWSTR", "LPTSTR", "PSTR", "PWSTR", "PTSTR", "PCHAR", "PWCHAR", "PUCHAR", "LPBYTE",
    "PBYTE", "LPVOID", "PVOID", "LPWORD", "PWORD", "LPDWORD", "PDWORD", "LPLONG", "PLONG",
    "PULONG", "LPINT", "PINT", "PUINT", "LPBOOL", "PBOOL", "PBOOLEAN", "LPHANDLE", "PHANDLE",
    "PFLOAT", "LPPOINT", "PPOINT", "LPRECT", "PRECT", "LPSIZE", "PSIZE",
];

pub struct Dcl05C {
    /// Names every scanned file's typedefs bind to a pointer type in this
    /// rule's sense, from prescan: the typedef usually lives in a
    /// header, and `const LPPOINT pt` in a .c file is only recognisable as
    /// "const on the pointer, not the pointee" if `LPPOINT` is known to be
    /// one.
    pointer_typedef_names: RefCell<Arc<HashSet<String>>>,
}

impl Dcl05C {
    pub fn new() -> Self {
        Self {
            pointer_typedef_names: RefCell::default(),
        }
    }
}

impl Default for Dcl05C {
    fn default() -> Self {
        Self::new()
    }
}

impl CertRule for Dcl05C {
    fn rule_id(&self) -> &'static str {
        "DCL05-C"
    }

    fn description(&self) -> &'static str {
        "Use typedefs of non-pointer types only"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "DCL05-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.pointer_typedef_names.borrow_mut() = context.pointer_typedef_names.clone();
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Every pointer typedef this file can see: its own, the project's
        // (prescan), and the Win32 ones no include path supplies.
        let mut known_pointer_typedefs = HashSet::clone(&self.pointer_typedef_names.borrow());
        known_pointer_typedefs.extend(WIN32_POINTER_TYPEDEFS.iter().map(|s| s.to_string()));

        check_typedef_declarations(node, source, &mut violations, &mut known_pointer_typedefs);
        check_const_qualified_pointer_typedef_use(
            node,
            source,
            &mut violations,
            &known_pointer_typedefs,
        );
        check_complex_function_pointers(node, source, &mut violations);

        violations
    }
}

/// Flag `typedef T *Name;` -- a typedef that hides a pointer, so that
/// `const Name x` const-qualifies the pointer rather than the pointee -- and
/// add each such name to `known`.
///
/// Only the typedef's own declarator chain is read
/// ([`pointer_typedef_names_in`]). Recursing into the whole
/// `type_definition` subtree, as this once did, reports `typedef struct s {
/// struct s *next; } s_t;` because a struct MEMBER is a pointer, and names the
/// first `type_identifier` it meets (the return type of a function-pointer
/// typedef, or the struct tag) rather than the name being defined.
///
/// Exempt, per the wiki: a pointer to const (`typedef const POINT *LPCPOINT`,
/// the const already sits on the pointee) and a function pointer type
/// ("Function pointer types are an exception to this recommendation").
fn check_typedef_declarations(
    node: &Node,
    source: &str,
    violations: &mut Vec<RuleViolation>,
    known: &mut HashSet<String>,
) {
    for n in query::find_descendants_of_kind(*node, "type_definition") {
        for typedef_name in pointer_typedef_names_in(&n, source) {
            violations.push(RuleViolation {
                rule_id: "DCL05-C".to_string(),
                file_path: "".to_string(),
                message: format!(
                    "Typedef '{}' defines a pointer type, which can cause confusion with const-qualification",
                    typedef_name
                ),
                // Reported at the `typedef` keyword, not the declarator:
                // ground_truth keys on this line for the Windows
                // `typedef struct { ... } T, *PT;` idiom, and moving it would
                // drop every labelled instance out of the denominator.
                line: n.start_position().row + 1,
                column: n.start_position().column,
                severity: Severity::Medium,
                suggestion: Some("Use typedef of non-pointer type and declare pointers explicitly at point of use".to_string()),
                requires_manual_review: Some(false),
            });
            known.insert(typedef_name);
        }
    }
}

/// Flag `const Name x` where `Name` is a known pointer typedef: the wiki's
/// Windows noncompliant example, `void func(const LPPOINT pt)`, where the
/// `const` lands on the pointer and `pt->x = 0` still compiles.
///
/// This is the whole of what the wiki says about USING a pointer typedef.
/// A bare `LPSTR lpBuffer` parameter is not called noncompliant anywhere on
/// the page -- the recommendation is about what to typedef, and the Win32
/// API's choices are not the caller's -- so it is not flagged. The earlier
/// version of this check guessed pointer-ness from the NAME (`P` + capital,
/// `LP`, `*PTR`) and flagged every use, const or not: on the real-world
/// suite that was 113 FP to 7 TP, the FPs being struct typedefs (`PHY_DRIVE_INFO`,
/// `PWInfo`, `PGconn`), integers (`LPARAM`, `ULONG_PTR`) and macros
/// (`PATH_MAX`, `PAGE_BITS`) that merely start with P.
///
/// Only a declarator that is the bare name qualifies: in `const LPPOINT *pp`
/// the const-qualified object is the pointee and the typedef is not hiding
/// anything from the reader of that line.
fn check_const_qualified_pointer_typedef_use(
    node: &Node,
    source: &str,
    violations: &mut Vec<RuleViolation>,
    known: &HashSet<String>,
) {
    for n in query::find_descendants_of_kinds(
        *node,
        &["parameter_declaration", "declaration", "field_declaration"],
    ) {
        let Some(type_node) = n.child_by_field_name("type") else {
            continue;
        };
        if type_node.kind() != "type_identifier" {
            continue;
        }
        let type_name = get_node_text(&type_node, source);
        if !known.contains(type_name) || !has_direct_const_qualifier(&n) {
            continue;
        }
        let mut cursor = n.walk();
        let plain_declarator = n
            .children_by_field_name("declarator", &mut cursor)
            .any(|d| {
                let bound = if d.kind() == "init_declarator" {
                    inner_declarator(&d)
                } else {
                    Some(d)
                };
                matches!(
                    bound.map(|b| b.kind()),
                    Some("identifier") | Some("field_identifier")
                )
            });
        if !plain_declarator {
            continue;
        }

        violations.push(RuleViolation {
            rule_id: "DCL05-C".to_string(),
            file_path: "".to_string(),
            message: format!(
                "'const' applied to pointer typedef '{}' qualifies the pointer, not the object it points to",
                type_name
            ),
            line: type_node.start_position().row + 1,
            column: type_node.start_position().column,
            severity: Severity::Medium,
            suggestion: Some(
                "Declare the pointee const explicitly (`const T *`), or define a pointer-to-const typedef such as `typedef const POINT *LPCPOINT;`"
                    .to_string(),
            ),
            requires_manual_review: Some(false),
        });
    }
}

/// Is `const` one of `n`'s own type qualifiers (not one inside a nested
/// declarator or parameter list)?
fn has_direct_const_qualifier(n: &Node) -> bool {
    let mut cursor = n.walk();
    let found = n.named_children(&mut cursor).any(|c| {
        c.kind() == "type_qualifier" && {
            let mut inner = c.walk();
            let is_const = c.children(&mut inner).any(|k| k.kind() == "const");
            is_const
        }
    });
    found
}

/// Kinds a function declarator can take (named and abstract).
const FUNCTION_DECLARATOR_KINDS: [&str; 2] =
    ["function_declarator", "abstract_function_declarator"];

/// Declarator wrappers that carry no type information of their own.
const PASSTHROUGH_DECLARATOR_KINDS: [&str; 2] = [
    "parenthesized_declarator",
    "abstract_parenthesized_declarator",
];

/// Declarator wrappers that add one level of indirection.
const POINTER_DECLARATOR_KINDS: [&str; 2] = ["pointer_declarator", "abstract_pointer_declarator"];

/// Flag function declarators whose type is hard to read without a typedef.
///
/// CERT's only noncompliant example is
/// `void (*signal(int, void (*)(int)))(int);`, whose compliant solution
/// typedefs the *function* type (`typedef void SighandlerType(int);`) and
/// spells the pointer at each use. Structurally, that is a declarator whose
/// RETURN type is a pointer to a function: the reader has to unwind the
/// declarator inside-out to find what `signal` is. That is the shape flagged
/// here, and only that shape.
///
/// A function-pointer parameter (`int (*f_rng)(void *, unsigned char *,
/// size_t)`, `qsort`'s comparator, `pthread_create`'s start routine) is the
/// universal C callback idiom and is NOT flagged, nor is a function pointer
/// whose own parameter list holds a callback (mbedtls's vtable-struct
/// members): CERT exempts function pointer types from this recommendation
/// outright, and nesting in a parameter list reads left to right like any
/// other parameter. The text heuristic this replaced (declaration text
/// containing `(*` and three parentheses) fired on the callback idiom alone
/// across mbedtls's adjudicated findings, and on an API header whose block
/// recovers as one `declaration` node it produced 428 findings on 9 lines.
///
/// Typedefs are skipped entirely: a typedef is the compliant form, and a
/// function pointer typedef is exempt by name.
fn check_complex_function_pointers(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
    let candidates: Vec<Node> = query::find_descendants_of_kinds(*node, &FUNCTION_DECLARATOR_KINDS)
        .into_iter()
        // A declarator tree-sitter could not finish is not evidence of nesting:
        // `MODULE_API int (*fn)(...)` with the macro unresolved parses as a
        // function declarator wrapping another with an ERROR between them.
        .filter(|n| !n.has_error())
        .filter(|n| returns_pointer_to_function(n))
        .filter(|n| query::nearest_ancestor_of_kind(*n, "type_definition").is_none())
        .collect();

    for n in candidates {
        // `void (*(*f(int))(int))(int)` qualifies at two levels; report the
        // outermost so one declaration is one finding.
        let has_complex_ancestor = query::find_ancestor(n, |a| {
            FUNCTION_DECLARATOR_KINDS.contains(&a.kind()) && returns_pointer_to_function(&a)
        })
        .is_some();
        if has_complex_ancestor {
            continue;
        }

        let name = declared_name(&n, source);
        let what = match name {
            Some(name) => format!("'{}'", name),
            None => "(unnamed)".to_string(),
        };
        violations.push(RuleViolation {
            rule_id: "DCL05-C".to_string(),
            file_path: "".to_string(),
            message: format!(
                "Function declarator {} returns a pointer to a function and is hard to read; \
                 declare the function type with a typedef",
                what
            ),
            line: n.start_position().row + 1,
            column: n.start_position().column,
            severity: Severity::Medium,
            suggestion: Some(
                "Typedef the function type, not the pointer (e.g. `typedef void HandlerType(int);`), \
                 then write the pointer at the point of use: `HandlerType *signal(int, HandlerType *)`"
                    .to_string(),
            ),
            requires_manual_review: Some(false),
        });
    }
}

/// True when a function declarator's declarator chain passes through a
/// pointer and then reaches another function declarator: `(*signal(...))(int)`
/// is parenthesized -> pointer -> function_declarator, a function returning a
/// pointer to a function.
///
/// The pointer is required, not incidental. C has no function returning a
/// function (C11 6.7.6.3p1), so a function declarator directly inside another
/// is always a misparse -- `void (callback)(dict *)` read as a function type
/// whose parameter has type `callback`, or `MACRO int(f)(int)` with the macro
/// unresolved -- and tree-sitter reports neither as an error.
fn returns_pointer_to_function(n: &Node) -> bool {
    let Some(inner) = n.child_by_field_name("declarator") else {
        return false;
    };
    let mut through_pointer = false;
    let mut cur = inner;
    loop {
        if FUNCTION_DECLARATOR_KINDS.contains(&cur.kind()) {
            return through_pointer;
        }
        if POINTER_DECLARATOR_KINDS.contains(&cur.kind()) {
            through_pointer = true;
        } else if !PASSTHROUGH_DECLARATOR_KINDS.contains(&cur.kind()) {
            return false;
        }
        // An abstract pointer declarator at the end of a chain has no inner
        // declarator at all.
        match inner_declarator(&cur) {
            Some(next) => cur = next,
            None => return false,
        }
    }
}

/// The identifier a (possibly nested) function declarator binds, if any:
/// the first identifier on its declarator chain, never a parameter name.
fn declared_name(n: &Node, source: &str) -> Option<String> {
    let mut cur = n.child_by_field_name("declarator")?;
    loop {
        if cur.kind() == "identifier" {
            return Some(get_node_text(&cur, source).to_string());
        }
        cur = inner_declarator(&cur)?;
    }
}
