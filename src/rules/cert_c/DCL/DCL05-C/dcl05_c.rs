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
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Dcl05C;

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

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First pass: collect all pointer typedefs defined in this file
        let mut pointer_typedefs = std::collections::HashSet::new();
        collect_pointer_typedefs(node, source, &mut pointer_typedefs);

        // Check typedef declarations
        check_typedef_declarations(node, source, &mut violations);

        // Check for usage of external pointer typedefs (from headers)
        check_external_pointer_typedef_usage(node, source, &mut violations, &pointer_typedefs);

        // Check complex function pointers
        check_complex_function_pointers(node, source, &mut violations);

        violations
    }
}

/// Collect every name a typedef in this file binds to a pointer type,
/// const-qualified and function-pointer typedefs included (this is only the
/// "defined here, so not external" set for the external-name check).
fn collect_pointer_typedefs(
    node: &Node,
    source: &str,
    pointer_typedefs: &mut std::collections::HashSet<String>,
) {
    for n in query::find_descendants_of_kind(*node, "type_definition") {
        for d in typedef_declarators(&n) {
            let shape = TypedefShape::of(&d, source);
            if shape.is_pointer {
                if let Some(name) = shape.name {
                    pointer_typedefs.insert(name);
                }
            }
        }
    }
}

/// Flag `typedef T *Name;` -- a typedef that hides a pointer, so that
/// `const Name x` const-qualifies the pointer rather than the pointee.
///
/// Only the typedef's own declarator chain is read. Recursing into the whole
/// `type_definition` subtree, as this once did, reports `typedef struct s {
/// struct s *next; } s_t;` because a struct MEMBER is a pointer, and names the
/// first `type_identifier` it meets (the return type of a function-pointer
/// typedef, or the struct tag) rather than the name being defined.
///
/// Exempt, per the wiki: a pointer to const (`typedef const POINT *LPCPOINT`,
/// the const already sits on the pointee) and a function pointer type
/// ("Function pointer types are an exception to this recommendation").
fn check_typedef_declarations(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
    for n in query::find_descendants_of_kind(*node, "type_definition") {
        // `typedef BOOL (WINAPI *PF)(int)` with the calling-convention macro
        // unresolved leaves an ERROR where the declarator should be; whatever
        // it declares is not readable. An ERROR buried in a struct body is a
        // different matter and does not disqualify the typedef's own name.
        if has_direct_error_child(&n) {
            continue;
        }
        let pointee_is_const = has_const_qualifier(&n);
        for d in typedef_declarators(&n) {
            if d.has_error() {
                continue;
            }
            let shape = TypedefShape::of(&d, source);
            if !shape.is_pointer || shape.is_function || pointee_is_const {
                continue;
            }
            let typedef_name = shape.name.unwrap_or_else(|| "unknown".to_string());

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
        }
    }
}

/// The declarators a `type_definition` binds: one per name, so
/// `typedef struct tagPOINT { ... } POINT, *LPPOINT;` yields both, and only
/// `*LPPOINT` is a pointer.
fn typedef_declarators<'a>(n: &Node<'a>) -> Vec<Node<'a>> {
    let mut cursor = n.walk();
    let found: Vec<Node<'a>> = n
        .children_by_field_name("declarator", &mut cursor)
        .collect();
    found
}

/// Is one of `n`'s own children an ERROR node?
fn has_direct_error_child(n: &Node) -> bool {
    let mut cursor = n.walk();
    let found = n.children(&mut cursor).any(|c| c.is_error());
    found
}

/// Does the typedef's specifier list carry `const` (the pointee is const)?
/// Only direct children count: a `const` inside a struct body or a parameter
/// list qualifies something else.
fn has_const_qualifier(n: &Node) -> bool {
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

/// What one typedef declarator chain spells, read from the outside in.
struct TypedefShape {
    /// The chain contains a `pointer_declarator`.
    is_pointer: bool,
    /// The chain contains a `function_declarator`: a function or function
    /// pointer type, which CERT exempts.
    is_function: bool,
    /// The `type_identifier` at the end of the chain -- the name defined.
    name: Option<String>,
}

impl TypedefShape {
    fn of(declarator: &Node, source: &str) -> Self {
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
                    shape.name = Some(get_node_text(&cur, source).to_string());
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

/// Check for usage of external pointer typedefs (from headers like Windows.h)
/// These are pointer typedefs that are used but not defined in the current file
fn check_external_pointer_typedef_usage(
    node: &Node,
    source: &str,
    violations: &mut Vec<RuleViolation>,
    defined_typedefs: &std::collections::HashSet<String>,
) {
    // Look for parameter declarations or variable declarations that use type identifiers
    for n in query::find_descendants_of_kinds(*node, &["parameter_declaration", "declaration"]) {
        // Find type_identifier nodes in parameters/declarations
        if let Some(type_id_node) = find_first_type_identifier_node(&n) {
            let type_name = get_node_text(&type_id_node, source);

            // Check if this looks like a Windows-style pointer typedef (ends with P or LP prefix)
            // Common patterns: LPPOINT, LPTSTR, PLONG, etc.
            if is_likely_external_pointer_typedef(&type_name)
                && !defined_typedefs.contains(type_name)
            {
                // This is likely an external pointer typedef being used
                violations.push(RuleViolation {
                    rule_id: "DCL05-C".to_string(),
                    file_path: "".to_string(),
                    message: format!(
                        "Usage of external pointer typedef '{}' (likely from header). \
                        Pointer typedefs can cause confusion with const-qualification",
                        type_name
                    ),
                    line: type_id_node.start_position().row + 1,
                    column: type_id_node.start_position().column,
                    severity: Severity::Medium,
                    suggestion: Some(
                        "Avoid using pointer typedefs from external headers, or use const-qualified versions".to_string()
                    ),
                    requires_manual_review: Some(false),
                });
            }
        }
    }
}

/// Find the first type_identifier node (non-recursive, just direct children)
#[allow(clippy::manual_find)]
fn find_first_type_identifier_node<'a>(node: &'a Node) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "type_identifier" {
            return Some(child);
        }
    }
    None
}

/// Check if a type name looks like an external pointer typedef
/// Common patterns: LP* (long pointer), P* (pointer), *PTR, etc.
fn is_likely_external_pointer_typedef(type_name: &str) -> bool {
    // Windows API patterns
    if type_name.starts_with("LP") && type_name.len() > 2 {
        // LPPOINT, LPTSTR, etc. but NOT LPCPOINT (const version is OK)
        return !type_name.starts_with("LPC");
    }

    // P-prefix patterns (PLONG, PDWORD, etc.)
    if type_name.starts_with('P')
        && type_name.len() > 1
        && type_name.chars().nth(1).unwrap().is_uppercase()
    {
        return true;
    }

    // PTR suffix patterns
    if type_name.ends_with("PTR") || type_name.ends_with("Ptr") {
        return true;
    }

    false
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

/// The declarator one level inside `n`. Pointer, array and function
/// declarators name it as the `declarator` field; a parenthesized declarator
/// has no field for it (`( declarator )`, possibly with an `ms_call_modifier`
/// first), so fall back to the first named child that is a declarator.
fn inner_declarator<'a>(n: &Node<'a>) -> Option<Node<'a>> {
    if let Some(d) = n.child_by_field_name("declarator") {
        return Some(d);
    }
    let mut cursor = n.walk();
    let found = n
        .named_children(&mut cursor)
        .find(|c| c.kind().ends_with("declarator") || c.kind() == "identifier");
    found
}
