// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! DCL37-C: Do not declare or define a reserved identifier
//!
//! This rule detects violations where code declares or defines identifiers
//! that are reserved by the C standard, including:
//! - Names starting with underscore followed by uppercase letter (_M, _A, etc.)
//! - Names starting with double underscore (__, ___foo, etc.)
//! - Names starting with an underscore, declared at file scope (C 7.1.3: a
//!   block-scope `_x` is not reserved, and neither is a block-scope
//!   `extern int _x;`, whose identifier has block scope too). Declarations
//!   inside `extern "C" { ... }` are at file scope.
//! - Reserved standard library names (errno, SIZE_MAX, etc.), where the file
//!   includes a header that defines the name (C 7.1.3), directly or through
//!   the headers it includes, by an `#include` not in another arm of the
//!   declaration's `#if` chain; `errno` everywhere
//!
//! Every declarator of a declaration is checked, through any pointer, array,
//! function or parenthesized declarator around its name (`int _a, *_b;`,
//! `int (*_fp)(void);`). An array's size is not a declared name, so
//! `char buf[_SIZE];` declares only `buf`. A function defined at file scope
//! is checked as a file-scope declaration is, so `static int _helper(void)`
//! is reported.
//!
//! A typedef name and an enumeration constant are ordinary identifiers, so
//! each is checked as a variable is, at file scope or in a block. A tag is
//! reserved at file scope as an ordinary identifier is, and is checked where
//! it is declared: a specifier with a body, or one standing alone
//! (`struct _tag;`). `struct _stat st;` only names a tag declared elsewhere.
//! Members and labels each have a name space of their own, which the
//! file-scope reservation does not reach, so only `_X` and `__x` are reported
//! there.
//!
//! Defining a feature-test macro is not reported. These names are reserved,
//! but a governing standard or the implementation's documentation tells the
//! program to define them to request features, so a program that does is
//! doing what that source asks. The exemption is the closed, cited list in
//! [`FEATURE_TEST_MACROS`], never a pattern, and it covers only defining a
//! listed name as an object-like macro, with any value; the value is not
//! checked. A function-like `#define _GNU_SOURCE() 1` is not the form any
//! source documents, so it is reported, and so are `_MY_SOURCE` and an
//! include guard such as `_FOO_H`. It applies under every preset. This is
//! aurora-lint's reading of the standards, recorded as a decision; CERT has
//! left the question open.
//!
//! Removing a macro definition of a name reserved for any use with `#undef`
//! is undefined (C 7.1.3), so `#undef _X` and `#undef __x` are reported, and
//! so is `#undef` of a listed feature-test macro: its exemption covers
//! defining it. `#undef NULL`, which C 7.1.4 allows, is not reported.
//!
//! CERT C reference:
//! <https://wiki.sei.cmu.edu/confluence/display/c/DCL37-C.+Do+not+declare+or+define+a+reserved+identifier>

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::{IncludeClosure, ProjectContext};
use crate::analyze::preproc_arms::PreprocArms;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{descendants_of_kinds_with, get_node_text};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use tree_sitter::Node;

/// The feature-test macros a program may define, each with the source that
/// tells it to. A closed list: a name not on it is reported, however much
/// it looks like one, and adding a name needs its source here.
/// `__STRICT_ANSI__` is left out on purpose: the compiler defines it (under
/// `-ansi` or `-std=c99`), not the program, so a program defining it is
/// reported.
pub const FEATURE_TEST_MACROS: &[(&str, &str)] = &[
    ("__STDC_WANT_LIB_EXT1__", "C23 (N3220) K.3.1.1"),
    ("__STDC_WANT_IEC_60559_EXT__", "C23 (N3220) 7.12"),
    ("__STDC_WANT_IEC_60559_TYPES_EXT__", "C23 (N3220) H.3"),
    ("_POSIX_C_SOURCE", "POSIX.1-2024 XSH 2.2.1.1"),
    ("_XOPEN_SOURCE", "POSIX.1-2024 XSH 2.2.1.2"),
    (
        "_POSIX_SOURCE",
        "POSIX.1-2024 XSH 2.2.1 (the POSIX.1-1990 macro, superseded by _POSIX_C_SOURCE)",
    ),
    (
        "_ISOC99_SOURCE",
        "glibc, feature_test_macros(7), man-pages 6.19",
    ),
    (
        "_ISOC11_SOURCE",
        "glibc, feature_test_macros(7), man-pages 6.19",
    ),
    (
        "_ISOC23_SOURCE",
        "glibc, feature_test_macros(7), man-pages 6.19",
    ),
    (
        "_ISOC2X_SOURCE",
        "glibc, feature_test_macros(7), man-pages 6.19",
    ),
    (
        "_LARGEFILE_SOURCE",
        "glibc, feature_test_macros(7), man-pages 6.19",
    ),
    (
        "_LARGEFILE64_SOURCE",
        "glibc, feature_test_macros(7), man-pages 6.19",
    ),
    (
        "_FILE_OFFSET_BITS",
        "glibc, feature_test_macros(7), man-pages 6.19",
    ),
    (
        "_TIME_BITS",
        "glibc, feature_test_macros(7), man-pages 6.19",
    ),
    (
        "_BSD_SOURCE",
        "glibc, feature_test_macros(7), man-pages 6.19",
    ),
    (
        "_SVID_SOURCE",
        "glibc, feature_test_macros(7), man-pages 6.19",
    ),
    (
        "_DEFAULT_SOURCE",
        "glibc, feature_test_macros(7), man-pages 6.19",
    ),
    (
        "_ATFILE_SOURCE",
        "glibc, feature_test_macros(7), man-pages 6.19",
    ),
    (
        "_GNU_SOURCE",
        "glibc, feature_test_macros(7), man-pages 6.19",
    ),
    (
        "_REENTRANT",
        "glibc, feature_test_macros(7), man-pages 6.19",
    ),
    (
        "_THREAD_SAFE",
        "glibc, feature_test_macros(7), man-pages 6.19",
    ),
    (
        "_FORTIFY_SOURCE",
        "glibc, feature_test_macros(7), man-pages 6.19",
    ),
];

/// Whether `name` is reserved for any use (C 7.1.3): it begins with two
/// underscores, or with an underscore and an uppercase letter.
fn is_reserved_for_any_use(name: &str) -> bool {
    name.starts_with("__")
        || name
            .strip_prefix('_')
            .and_then(|rest| rest.chars().next())
            .is_some_and(char::is_uppercase)
}

/// Every declarator of `node` (a declaration, typedef or member
/// declaration), with each `init_declarator`'s initializer left behind.
fn declarators<'a>(node: &Node<'a>) -> Vec<Node<'a>> {
    let mut cursor = node.walk();
    node.children_by_field_name("declarator", &mut cursor)
        .map(|d| {
            if d.kind() == "init_declarator" {
                d.child_by_field_name("declarator").unwrap_or(d)
            } else {
                d
            }
        })
        .collect()
}

/// The declarator a pointer, array, function, parenthesized or attributed
/// declarator wraps. An array's size and a function's parameters are not
/// part of it.
fn inner_declarator<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    match node.kind() {
        "parenthesized_declarator" | "attributed_declarator" => {
            let mut cursor = node.walk();
            let inner = node
                .named_children(&mut cursor)
                .find(|c| c.kind() != "attribute_declaration" && c.kind() != "ms_call_modifier");
            inner
        }
        _ => node.child_by_field_name("declarator"),
    }
}

/// The name `declarator` declares, found through any pointer, array,
/// function or parenthesized declarators around it.
fn declared_name(declarator: Node) -> Option<Node> {
    let mut node = declarator;
    loop {
        match node.kind() {
            "identifier" | "type_identifier" | "field_identifier" => return Some(node),
            "pointer_declarator"
            | "array_declarator"
            | "function_declarator"
            | "parenthesized_declarator"
            | "attributed_declarator" => node = inner_declarator(&node)?,
            _ => return None,
        }
    }
}

/// The tag a struct, union or enum specifier declares: one with a body, or
/// one that is the whole declaration (`struct _tag;`). `struct _stat st;`
/// only refers to a tag declared elsewhere, so it declares none here.
fn declared_tag<'a>(specifier: &Node<'a>) -> Option<Node<'a>> {
    let name = specifier.child_by_field_name("name")?;
    let defines = specifier.child_by_field_name("body").is_some();
    let stands_alone = specifier.next_sibling().is_some_and(|s| s.kind() == ";");
    (defines || stands_alone).then_some(name)
}

fn reserved_identifier(node: &Node, name: &str) -> RuleViolation {
    RuleViolation {
        rule_id: "DCL37-C".to_string(),
        severity: Severity::Low,
        line: node.start_position().row + 1,
        column: node.start_position().column + 1,
        message: format!("Reserved identifier '{}' should not be used", name),
        file_path: String::new(),
        suggestion: Some("Use a non-reserved identifier".to_string()),
        requires_manual_review: Some(false),
    }
}

fn file_scope_identifier(node: &Node, name: &str) -> RuleViolation {
    RuleViolation {
        rule_id: "DCL37-C".to_string(),
        severity: Severity::Low,
        line: node.start_position().row + 1,
        column: node.start_position().column + 1,
        message: format!(
            "File-scope identifier '{}' should not start with underscore",
            name
        ),
        file_path: String::new(),
        suggestion: Some("Remove the leading underscore or rename the identifier".to_string()),
        requires_manual_review: Some(false),
    }
}

/// Whether `name` is on [`FEATURE_TEST_MACROS`].
fn is_feature_test_macro(name: &str) -> bool {
    FEATURE_TEST_MACROS
        .iter()
        .any(|(listed, _)| *listed == name)
}

/// Library names a program may not declare, each with the standard headers
/// that declare or define it. C 7.1.3 reserves such a name only where the
/// file includes one of those headers; `errno`, which it reserves for
/// external linkage always and whose definition by a program C 7.5p2 makes
/// undefined, has none and is reserved everywhere.
const RESERVED_NAMES: &[(&str, &[&str])] = &[
    ("errno", &[]),
    ("SIZE_MAX", &["stdint.h"]),
    ("INT_MAX", &["limits.h"]),
    ("INT_MIN", &["limits.h"]),
    ("UINT_MAX", &["limits.h"]),
    ("LONG_MAX", &["limits.h"]),
    ("LONG_MIN", &["limits.h"]),
    ("ULONG_MAX", &["limits.h"]),
    ("CHAR_MAX", &["limits.h"]),
    ("CHAR_MIN", &["limits.h"]),
    ("SHRT_MAX", &["limits.h"]),
    ("SHRT_MIN", &["limits.h"]),
    ("USHRT_MAX", &["limits.h"]),
    ("LLONG_MAX", &["limits.h"]),
    ("LLONG_MIN", &["limits.h"]),
    ("ULLONG_MAX", &["limits.h"]),
    ("NULL", NULL_HEADERS),
    ("true", &["stdbool.h"]),
    ("false", &["stdbool.h"]),
    ("bool", &["stdbool.h"]),
    ("stdin", &["stdio.h"]),
    ("stdout", &["stdio.h"]),
    ("stderr", &["stdio.h"]),
    ("FILE", &["stdio.h"]),
    ("EOF", &["stdio.h"]),
];

/// The headers that define `NULL` (C11 7.11, 7.19, 7.21.1, 7.22, 7.24.1,
/// 7.27.1, 7.29.1).
const NULL_HEADERS: &[&str] = &[
    "locale.h", "stddef.h", "stdio.h", "stdlib.h", "string.h", "time.h", "wchar.h",
];

/// Headers a standard header is defined to include, so that including the
/// first includes the second: `<inttypes.h>` includes `<stdint.h>` (C11
/// 7.8p1).
const IMPLIED_HEADERS: &[(&str, &str)] = &[("inttypes.h", "stdint.h")];

/// `path` with its `.` segments dropped and each `..` removing the segment
/// before it, `/`-separated; with `relative`, a `..` with nothing before it
/// is dropped too, leaving the part of the path it names below its
/// includer, as [`IncludeClosure`] keeps an unresolved spelling.
fn normalized(path: &str, relative: bool) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split(['/', '\\']) {
        match segment {
            "." => {}
            "" if !segments.is_empty() => {}
            ".." => {
                if segments.last().is_some_and(|s| !s.is_empty() && *s != "..") {
                    segments.pop();
                } else if !relative {
                    segments.push(segment);
                }
            }
            _ => segments.push(segment),
        }
    }
    segments.join("/")
}

/// The standard headers [`RESERVED_NAMES`] names that `closure` reaches, by
/// the spelling of an include that resolved to no file or the name of one
/// that did, with the headers they are defined to include.
fn headers_reached(closure: &IncludeClosure) -> HashSet<&'static str> {
    let mut headers: HashSet<&'static str> = RESERVED_NAMES
        .iter()
        .flat_map(|(_, headers)| headers.iter().copied())
        .chain(IMPLIED_HEADERS.iter().map(|(header, _)| *header))
        .filter(|header| {
            closure.unresolved.contains(*header)
                || closure
                    .files
                    .iter()
                    .any(|f| f.strip_suffix(header).is_some_and(|dir| dir.ends_with('/')))
        })
        .collect();
    for (header, implied) in IMPLIED_HEADERS {
        if headers.contains(header) {
            headers.insert(implied);
        }
    }
    headers
}

/// The standard headers a file includes, and where. A header counts for a
/// declaration unless the only `#include` lines bringing it in sit in
/// another arm of an `#if` chain than the declaration: raylib's
/// `typedef enum bool { false, true } bool;` is the `#elif` of an
/// `#include <stdbool.h>`, so no build has both (ADR-0010 decision 4). An
/// `#include` in `#if 0`, a `__cplusplus` arm, or an `#ifdef` arm the
/// file's own `#define`/`#undef` rule out counts nowhere; one under a
/// platform macro such as `_WIN32` counts.
/// **Limitation:** arms are told apart within one chain only, so an
/// `#include` under `#if C99` and a declaration under a separate
/// `#if !C99` still count together, which errs toward reporting.
#[derive(Debug, Default)]
struct IncludedHeaders {
    /// What the build's forced includes bring in, everywhere.
    everywhere: HashSet<&'static str>,
    /// Each `#include` line's byte offset, and what it brings in: the header
    /// it names, and every header that one includes when it resolved to a
    /// file.
    lines: Vec<(usize, HashSet<&'static str>)>,
    arms: Option<PreprocArms>,
}

impl IncludedHeaders {
    fn of(root: &Node, source: &str, edges: &HashMap<String, Vec<String>>, path: &Path) -> Self {
        let file = crate::analyze::compile_commands::real_path(path);
        let targets = edges.get(&file).cloned().unwrap_or_default();
        let dir = file.rsplit_once('/').map_or("", |(dir, _)| dir);
        // Only an `#include` some build compiles counts: one in `#if 0`, a
        // `__cplusplus` arm or an arm the file's own `#define`s rule out
        // never is, and one in a comment is no node. The platform profile
        // does not decide it (ADR-0010 D3): an include under `#ifdef _WIN32`
        // counts.
        let dead: Vec<(usize, usize)> = lang_parsing_substrate::dead_code_ranges(source)
            .into_iter()
            .map(|r| (r.start_line, r.end_line))
            .collect();
        let lines: Vec<(usize, HashSet<&'static str>)> =
            query::find_descendants_of_kinds(*root, &["preproc_include"])
                .into_iter()
                .filter(|include| {
                    let line = include.start_position().row + 1;
                    !dead
                        .iter()
                        .any(|&(start, end)| (start..=end).contains(&line))
                })
                .filter_map(|include| {
                    let path = include.child_by_field_name("path")?;
                    let text = get_node_text(&path, source);
                    let spelling = text.trim().trim_matches(['<', '>', '"']).trim();
                    let mut closure = IncludeClosure::default();
                    closure.unresolved.insert(normalized(spelling, true));
                    // The file the line resolved to, and what it includes:
                    // the one beside the includer when a quoted spelling
                    // names it, else those ending in the spelling.
                    let beside = normalized(&format!("{dir}/{spelling}"), false);
                    let tail = format!("/{}", normalized(spelling, true));
                    let resolved: Vec<&String> = if targets.contains(&beside) {
                        vec![&beside]
                    } else {
                        targets.iter().filter(|t| t.ends_with(&tail)).collect()
                    };
                    for target in resolved {
                        if let Some(reached) = IncludeClosure::of(edges, Path::new(target)) {
                            closure.files.extend(reached.files);
                            closure.unresolved.extend(reached.unresolved);
                        }
                        closure.files.insert(target.clone());
                    }
                    Some((include.start_byte(), headers_reached(&closure)))
                })
                .filter(|(_, headers)| !headers.is_empty())
                .collect();
        let arms = (!lines.is_empty()).then(|| PreprocArms::collect(root));
        let everywhere = IncludeClosure::of_forced_includes(&[edges])
            .map(|forced| headers_reached(&forced))
            .unwrap_or_default();
        IncludedHeaders {
            everywhere,
            lines,
            arms,
        }
    }

    /// Whether a declaration at byte offset `at` sees `header` included.
    fn includes(&self, header: &str, at: usize) -> bool {
        self.everywhere.contains(header)
            || self.lines.iter().any(|(offset, headers)| {
                headers.contains(header)
                    && !self
                        .arms
                        .as_ref()
                        .is_some_and(|arms| arms.exclusive(*offset, at))
            })
    }
}

// Standard library function names with external linkage
const RESERVED_FUNCTIONS: &[&str] = &[
    "malloc", "calloc", "realloc", "free", "printf", "scanf", "fprintf", "sprintf", "fopen",
    "fclose", "fread", "fwrite", "memcpy", "memset", "strlen", "strcpy", "strcat", "strcmp",
    "exit", "abort",
];

#[derive(Debug, Default)]
pub struct Dcl37C {
    include_edges: RefCell<Arc<HashMap<String, Vec<String>>>>,
    file_path: RefCell<String>,
    /// The standard headers the scanned file includes.
    included: RefCell<IncludedHeaders>,
}

impl Dcl37C {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if an identifier is a reserved identifier per C standard: one
    /// reserved for any use, or a library name where the declaration at
    /// byte offset `at` sees a header of it included.
    fn is_reserved_identifier(&self, name: &str, at: usize) -> bool {
        is_reserved_for_any_use(name)
            || RESERVED_NAMES.iter().any(|(listed, headers)| {
                *listed == name
                    && (headers.is_empty()
                        || headers
                            .iter()
                            .any(|h| self.included.borrow().includes(h, at)))
            })
    }

    /// Check if a name is a reserved function name
    fn is_reserved_function(&self, name: &str) -> bool {
        RESERVED_FUNCTIONS.contains(&name)
    }

    /// Check if identifier starts with underscore (reserved at file scope)
    fn has_file_scope_reserved_prefix(&self, name: &str) -> bool {
        name.starts_with('_')
    }

    /// Check declarations for reserved identifiers
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Only a file-scope declaration reserves every leading-underscore
        // name; at block scope, `_x` is not reserved (C 7.1.3). A
        // declaration is at block scope when it lies in a function: in its
        // body, a `for` header, a parameter list or a K&R parameter
        // declaration. Everywhere else (`#if` arms, `extern "C" { ... }`,
        // a parser `ERROR`) it is at file scope.
        let block_scope: HashSet<usize> = descendants_of_kinds_with(
            *node,
            &[
                "declaration",
                "function_definition",
                "type_definition",
                "struct_specifier",
                "union_specifier",
                "enum_specifier",
                "enumerator",
            ],
            false,
            |inside, parent| {
                *inside
                    || matches!(
                        parent.kind(),
                        "compound_statement"
                            | "for_statement"
                            | "parameter_list"
                            | "function_definition"
                    )
            },
        )
        .into_iter()
        .filter(|(_, inside)| *inside)
        .map(|(decl, _)| decl.id())
        .collect();
        for n in query::find_descendants(*node, |_| true) {
            let at_file_scope = !block_scope.contains(&n.id());
            match n.kind() {
                "declaration" => {
                    for declarator in declarators(&n) {
                        if at_file_scope {
                            self.check_file_scope_declarator(&declarator, source, violations);
                        } else {
                            self.check_declarator(&declarator, source, violations);
                        }
                    }
                }
                "preproc_def" | "preproc_function_def" => {
                    self.check_preproc_def(&n, source, violations);
                }
                "preproc_call" => {
                    self.check_undef(&n, source, violations);
                }
                "function_definition" => {
                    if let Some(declarator) = n.child_by_field_name("declarator") {
                        // Function definitions: check against reserved function names and patterns
                        self.check_function_declarator(
                            &declarator,
                            source,
                            at_file_scope,
                            violations,
                        );
                    }
                }
                "parameter_declaration" => {
                    if let Some(declarator) = n.child_by_field_name("declarator") {
                        self.check_declarator(&declarator, source, violations);
                    }
                }
                // A typedef name and an enumeration constant are ordinary
                // identifiers, and a tag is in the tag name space; C 7.1.3
                // reserves a leading-underscore name in both at file scope.
                "type_definition" => {
                    for declarator in declarators(&n) {
                        if let Some(name) = declared_name(declarator) {
                            self.check_name(&name, source, at_file_scope, true, violations);
                        }
                    }
                }
                "enumerator" => {
                    if let Some(name) = n.child_by_field_name("name") {
                        self.check_name(&name, source, at_file_scope, true, violations);
                    }
                }
                "struct_specifier" | "union_specifier" | "enum_specifier" => {
                    if let Some(name) = declared_tag(&n) {
                        self.check_name(&name, source, at_file_scope, false, violations);
                    }
                }
                // Members and labels each have a name space of their own,
                // which the file-scope reservation does not reach, so only
                // a name reserved for any use is reported there.
                "field_declaration" => {
                    for declarator in declarators(&n) {
                        if let Some(name) = declared_name(declarator) {
                            self.check_name(&name, source, false, false, violations);
                        }
                    }
                }
                "labeled_statement" => {
                    if let Some(label) = n.child_by_field_name("label") {
                        self.check_name(&label, source, false, false, violations);
                    }
                }
                _ => {}
            }
        }
    }

    /// Report a declared typedef name, tag, enumeration constant, member or
    /// label that is reserved: for any use (`_X`, `__x`), or, where
    /// `file_scope` holds, any leading-underscore name. An `ordinary`
    /// identifier (a typedef name or enumeration constant, as against a tag,
    /// member or label) is also checked against the library names a
    /// variable is.
    fn check_name(
        &self,
        node: &Node,
        source: &str,
        file_scope: bool,
        ordinary: bool,
        violations: &mut Vec<RuleViolation>,
    ) {
        let name = get_node_text(node, source);
        let reserved = if ordinary {
            self.is_reserved_identifier(&name, node.start_byte())
        } else {
            is_reserved_for_any_use(&name)
        };
        if reserved {
            violations.push(reserved_identifier(node, &name));
        } else if file_scope && self.has_file_scope_reserved_prefix(&name) {
            violations.push(file_scope_identifier(node, &name));
        }
    }

    /// Check function declarators for reserved function names. A function
    /// defined at file scope, as every standard C function is, also has the
    /// leading-underscore names reserved there.
    fn check_function_declarator(
        &self,
        node: &Node,
        source: &str,
        file_scope: bool,
        violations: &mut Vec<RuleViolation>,
    ) {
        match node.kind() {
            "identifier" => {
                let name = get_node_text(node, source);
                // Check against reserved function names
                if self.is_reserved_function(&name) {
                    violations.push(RuleViolation {
                        rule_id: "DCL37-C".to_string(),
                        severity: Severity::Low,
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        message: format!(
                            "Reserved function name '{}' should not be redefined",
                            name
                        ),
                        file_path: String::new(),
                        suggestion: Some("Use a different function name".to_string()),
                        requires_manual_review: Some(false),
                    });
                }
                // Also check general reserved identifier patterns
                if self.is_reserved_identifier(&name, node.start_byte()) {
                    violations.push(RuleViolation {
                        rule_id: "DCL37-C".to_string(),
                        severity: Severity::Low,
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        message: format!(
                            "Reserved identifier '{}' should not be used as function name",
                            name
                        ),
                        file_path: String::new(),
                        suggestion: Some("Use a non-reserved function name".to_string()),
                        requires_manual_review: Some(false),
                    });
                } else if file_scope && self.has_file_scope_reserved_prefix(&name) {
                    violations.push(file_scope_identifier(node, &name));
                }
            }
            "function_declarator"
            | "pointer_declarator"
            | "parenthesized_declarator"
            | "attributed_declarator" => {
                if let Some(declarator) = inner_declarator(node) {
                    self.check_function_declarator(&declarator, source, file_scope, violations);
                }
            }
            _ => {}
        }
    }

    /// Check file-scope declarators for underscore-prefixed identifiers
    fn check_file_scope_declarator(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(node) = declared_name(*node) {
            let name = get_node_text(&node, source);
            // At file scope, any identifier starting with underscore is
            // reserved. A name reserved for any use is reported once, as
            // that.
            if self.is_reserved_identifier(&name, node.start_byte()) {
                violations.push(reserved_identifier(&node, &name));
            } else if self.has_file_scope_reserved_prefix(&name) {
                violations.push(file_scope_identifier(&node, &name));
            }
        }
    }

    /// Check a block-scope or parameter declarator for a reserved identifier
    fn check_declarator(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(node) = declared_name(*node) {
            let name = get_node_text(&node, source);
            if self.is_reserved_identifier(&name, node.start_byte()) {
                violations.push(reserved_identifier(&node, &name));
            }
        }
    }

    /// Report `#undef` of a name reserved for any use: removing a macro
    /// definition of one is undefined (C 7.1.3). A listed feature-test
    /// macro is not exempt; its exemption covers defining it. An `#undef`
    /// of a library macro such as `NULL` or `errno` is not reported here.
    fn check_undef(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let is_undef = node.child_by_field_name("directive").is_some_and(|d| {
            let text = get_node_text(&d, source);
            text.trim_start_matches('#').trim() == "undef"
        });
        let Some(argument) = node.child_by_field_name("argument").filter(|_| is_undef) else {
            return;
        };
        let text = get_node_text(&argument, source);
        let Some(name) = text.split_whitespace().next() else {
            return;
        };
        if is_reserved_for_any_use(name) {
            let offset = text.find(name).unwrap_or(0);
            let start = argument.start_position();
            violations.push(RuleViolation {
                rule_id: "DCL37-C".to_string(),
                severity: Severity::Low,
                line: start.row + 1,
                column: start.column + offset + 1,
                message: format!(
                    "Reserved identifier '{}' should not be removed with #undef",
                    name
                ),
                file_path: String::new(),
                suggestion: Some(
                    "Do not #undef a reserved macro; use a non-reserved macro name".to_string(),
                ),
                requires_manual_review: Some(false),
            });
        }
    }

    /// Check macro definitions for reserved identifiers. Defining a listed
    /// feature-test macro as an object-like macro is what its source asks
    /// of the program, so it is not reported, whatever its value
    /// ([`FEATURE_TEST_MACROS`]).
    fn check_preproc_def(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = get_node_text(&name_node, source);
            let exempt = node.kind() == "preproc_def" && is_feature_test_macro(&name);
            if self.is_reserved_identifier(&name, name_node.start_byte()) && !exempt {
                violations.push(RuleViolation {
                    rule_id: "DCL37-C".to_string(),
                    severity: Severity::Low,
                    line: name_node.start_position().row + 1,
                    column: name_node.start_position().column + 1,
                    message: format!(
                        "Reserved identifier '{}' should not be used as a macro name",
                        name
                    ),
                    file_path: String::new(),
                    suggestion: Some("Use a non-reserved macro name".to_string()),
                    requires_manual_review: Some(false),
                });
            }
        }
    }
}

impl CertRule for Dcl37C {
    fn rule_id(&self) -> &'static str {
        "DCL37-C"
    }

    fn description(&self) -> &'static str {
        "Do not declare or define a reserved identifier"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "DCL37-C"
    }

    fn scan(&self, root_node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        *self.included.borrow_mut() = IncludedHeaders::of(
            root_node,
            source,
            &self.include_edges.borrow(),
            Path::new(&*self.file_path.borrow()),
        );
        self.check_node(root_node, source, violations);
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.include_edges.borrow_mut() = Arc::clone(&context.include_edges);
    }

    fn set_file_path(&self, path: &Path) {
        *self.file_path.borrow_mut() = path.to_string_lossy().into_owned();
    }
}
