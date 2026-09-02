// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! DCL31-C: Declare identifiers before using them
//!
//! This rule enforces that all identifiers must be explicitly declared with
//! complete type information before use. It detects:
//! - Missing type specifiers in declarations (e.g., `extern foo;`)
//! - Implicit function declarations (calling undeclared functions)
//! - Implicit return types in function definitions
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/DCL31-C.+Declare+identifiers+before+using+them

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{self, get_node_text};
use crate::utility::cert_c::declarator_utils;
use crate::utility::cert_c::std_functions;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashSet;
use tree_sitter::Node;

#[derive(Debug)]
pub struct Dcl31C {
    // Track declared functions to detect implicit declarations
    declared_functions: RefCell<HashSet<String>>,
    // Functions known from pre-scanned directories (cross-file context)
    cross_file_functions: RefCell<HashSet<String>>,
    // Object-macro names known from pre-scanned directories (cross-file context)
    cross_file_macro_names: RefCell<HashSet<String>>,
    // True when the project includes a header it doesn't ship (generated at
    // build time), so no set of declarations we can collect is complete.
    // See `declarations_are_incomplete`.
    incomplete_declarations: RefCell<bool>,
}

impl Dcl31C {
    pub fn new() -> Self {
        Dcl31C {
            declared_functions: RefCell::new(HashSet::new()),
            cross_file_functions: RefCell::new(HashSet::new()),
            cross_file_macro_names: RefCell::new(HashSet::new()),
            incomplete_declarations: RefCell::new(false),
        }
    }

    /// True if `name` is a known `#define`d macro, either in this file
    /// (text scan) or cross-file (prescan-collected `ProjectContext`).
    fn is_known_macro(&self, name: &str, source: &str) -> bool {
        ast_utils::is_defined_macro_name(name, source)
            || self.cross_file_macro_names.borrow().contains(name)
    }

    /// Check if a declaration has an explicit type specifier
    fn has_type_specifier(&self, node: &Node, source: &str) -> bool {
        let mut cursor = node.walk();
        let mut has_storage_class = false;
        let mut has_explicit_type = false;
        let mut has_real_declarator = false;
        let mut type_identifier_name: Option<String> = None;

        for child in node.children(&mut cursor) {
            let kind = child.kind();
            // Type specifiers in C - explicit types
            if matches!(
                kind,
                "primitive_type"
                    | "sized_type_specifier"
                    | "struct_specifier"
                    | "union_specifier"
                    | "enum_specifier"
            ) {
                has_explicit_type = true;
            }
            // `macro_type_specifier` (tree-sitter-c's node for a leading
            // `IDENTIFIER(args)` in a declaration's type position) only ever
            // appears for actual call-shaped text -- it's never how a
            // genuinely missing type parses (that's a bare `identifier`/
            // `type_identifier`, no parens). In practice it shows up when a
            // trailing or leading GCC-style attribute macro invocation
            // (`ALIGN(...)`, `VISIBLE`, `SKIM_BSS`) confuses the grammar
            // into splitting off a bogus extra `declaration` for the
            // attribute tail (task 650, seL4 e.g. `pml4e_t arr[N]
            // ALIGN(BIT(X)) VISIBLE;` -> a real `pml4e_t arr[N]` declaration
            // plus a second, spurious `ALIGN(BIT(X)) VISIBLE;` "declaration"
            // with no recognizable type). Since sqc can't tell that shape
            // apart from a real macro-based declaration without expanding
            // the macro, treat its presence as satisfying "has a type" --
            // conservative in both directions, and this rule's low-severity,
            // implicit-int-shaped intent was never about macro internals.
            if kind == "macro_type_specifier" {
                has_explicit_type = true;
            }
            // type_identifier could be a typedef or could be the variable name
            // if tree-sitter is confused about implicit int
            if kind == "type_identifier" {
                type_identifier_name = Some(get_node_text(&child, source).to_string());
            }
            // Track storage class specifiers like extern, static
            if kind == "storage_class_specifier" {
                has_storage_class = true;
            }
            // Track if we have a real declarator (non-empty identifier or declarator node)
            if kind == "identifier" {
                let text = get_node_text(&child, source);
                if !text.is_empty() {
                    has_real_declarator = true;
                }
            } else if kind.contains("declarator") {
                has_real_declarator = true;
            }
        }

        // Special case: "extern foo;" - tree-sitter parses this as:
        // - storage_class_specifier: "extern"
        // - type_identifier: "foo" (interpreted as the type)
        // - identifier: "" (empty!)
        // This is actually implicit int - foo is the variable name, not a type
        if has_storage_class && type_identifier_name.is_some() && !has_real_declarator {
            return false;
        }

        // If we have a storage class but no type at all, this is implicit int
        if has_storage_class && !has_explicit_type && type_identifier_name.is_none() {
            return false;
        }

        has_explicit_type || type_identifier_name.is_some()
    }

    /// Check for missing type specifier in declaration
    fn check_declaration(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() == "declaration" {
            if !self.has_type_specifier(node, source) {
                violations.push(RuleViolation {
                    rule_id: "DCL31-C".to_string(),
                    severity: Severity::Low,
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    message: "Declaration is missing an explicit type specifier".to_string(),
                    file_path: String::new(),
                    suggestion: Some(
                        "Add an explicit type specifier to the declaration".to_string(),
                    ),
                    requires_manual_review: Some(false),
                });
            }
        }
    }

    /// Track function declarations
    fn track_function_declaration(&self, node: &Node, source: &str) {
        if node.kind() == "function_definition" || node.kind() == "declaration" {
            if let Some(declarator) = node.child_by_field_name("declarator") {
                if let Some(func_name) = self.extract_function_name(&declarator, source) {
                    self.declared_functions.borrow_mut().insert(func_name);
                }
            }
        }
        // Function-pointer-typed parameters (e.g. `int (*xToken)(void*, int)`
        // in sqlite's callback style) are directly callable by name inside
        // the function body. They never reach the branch above because a
        // `parameter_declaration` node's kind is neither "function_definition"
        // nor "declaration", so they were falling through as apparently
        // undeclared calls (task 691).
        if node.kind() == "function_definition" {
            for name in function_pointer_param_names(node, source) {
                self.declared_functions.borrow_mut().insert(name);
            }
        }
        // Track function-like macro names (#define FOO(...) ...)
        // so that macro invocations aren't flagged as undeclared functions.
        if node.kind() == "preproc_function_def" {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = get_node_text(&name_node, source).to_string();
                self.declared_functions.borrow_mut().insert(name);
            }
        }
    }

    /// Extract function name from declarator.
    ///
    /// `T name = value;` — the declaration's "declarator" field is the
    /// `init_declarator` wrapping the real declarator, not the declarator
    /// itself. Without unwrapping it here, an initialized local (including a
    /// function-pointer local like `int (*xLocal)(int) = 0;`) is silently
    /// never tracked (task 691). Delegates everything else to
    /// `ast_utils::get_identifier_from_declarator`, which already handles
    /// `function_declarator`/`pointer_declarator`/`array_declarator`/
    /// `parenthesized_declarator` recursion (needed for the parenthesized
    /// `(*name)` shape of a function-pointer declarator) and plain
    /// identifiers.
    fn extract_function_name(&self, node: &Node, source: &str) -> Option<String> {
        let node = if node.kind() == "init_declarator" {
            node.child_by_field_name("declarator")?
        } else {
            *node
        };
        let name = ast_utils::get_identifier_from_declarator(&node, source);
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }

    /// Check for implicit function declaration in call expression
    fn check_function_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                // Skip indirect calls through function pointers or struct members.
                // e.g., self->callback(args), obj.handler(args), array[i](args)
                // These are not direct calls to named functions — they cannot be
                // "declared" in the traditional sense.
                if function.kind() != "identifier" {
                    return;
                }

                // The project generates part of its own declarations at build
                // time and we can't run that step, so "no declaration found"
                // is not evidence of an implicit declaration here — the same
                // reasoning as the preprocessor-conditional skip below,
                // applied to a whole missing header. See
                // `ProjectContext::unresolved_project_headers`.
                if *self.incomplete_declarations.borrow() {
                    return;
                }

                let func_name = get_node_text(&function, source);

                // Skip ALL_CAPS identifiers — in C, all-uppercase names are macros by
                // convention. Tree-sitter cannot expand macros, so it sees macro
                // invocations like SAFE_PRINT(x) or CU_ASSERT_EQUAL(a,b) as function
                // calls. They are never truly undeclared functions.
                if is_macro_like_name(func_name) || self.is_known_macro(func_name, source) {
                    return;
                }

                // `defined` is a preprocessor operator, not a function.
                // Tree-sitter parses `#if defined(X)` conditions and `defined`
                // appears as a call_expression identifier.
                if func_name == "defined" {
                    return;
                }

                // Names starting with '_' are compiler/implementation-defined intrinsics
                // (e.g., _nop(), _clrwdt() on Holtek MCUs). We cannot know their
                // declarations without vendor headers, so skip them.
                if func_name.starts_with('_') {
                    return;
                }

                // Skip known standard library functions unconditionally.
                // Tree-sitter cannot follow #include directives, so header-aware
                // checking produces FPs whenever headers are included transitively.
                if std_functions::is_known_standard_function(func_name) {
                    return;
                }

                // Skip if explicitly declared in this file
                if self.declared_functions.borrow().contains(func_name) {
                    return;
                }

                // Skip if known from pre-scanned directories
                if self.cross_file_functions.borrow().contains(func_name) {
                    return;
                }

                // Skip calls inside preprocessor conditionals (#ifdef, #if, #elif).
                // The corresponding declaration may be in a conditionally-included
                // header that tree-sitter cannot see.
                if is_inside_preproc_conditional(node) {
                    return;
                }

                violations.push(RuleViolation {
                    rule_id: "DCL31-C".to_string(),
                    severity: Severity::Low,
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    message: format!(
                        "Function '{}' is called without prior declaration",
                        func_name
                    ),
                    file_path: String::new(),
                    suggestion: Some(
                        "Declare the function before calling it or include the appropriate header"
                            .to_string(),
                    ),
                    requires_manual_review: Some(false),
                });
            }
        }
    }

    /// Check if function definition has explicit return type
    fn check_function_definition(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() == "function_definition" {
            if !self.has_type_specifier(node, source) {
                violations.push(RuleViolation {
                    rule_id: "DCL31-C".to_string(),
                    severity: Severity::Low,
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    message: "Function definition is missing an explicit return type".to_string(),
                    file_path: String::new(),
                    suggestion: Some(
                        "Add an explicit return type to the function definition".to_string(),
                    ),
                    requires_manual_review: Some(false),
                });
            }
        }
    }

    /// Recursively traverse AST
    fn traverse(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |_| true) {
            // Track declarations
            self.track_function_declaration(&n, source);

            // Check for violations
            self.check_declaration(&n, source, violations);
            self.check_function_call(&n, source, violations);
            self.check_function_definition(&n, source, violations);
        }
    }
}

impl CertRule for Dcl31C {
    fn rule_id(&self) -> &'static str {
        "DCL31-C"
    }

    fn description(&self) -> &'static str {
        "Declare identifiers before using them"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "DCL31-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        let mut funcs = context.known_functions.clone();
        // Header-declared functions (extern prototypes in .h files) are valid targets.
        funcs.extend(context.header_declared_functions.clone());
        for alias_name in context.macro_aliases.keys() {
            funcs.insert(alias_name.clone());
        }
        // Function-like macro invocations are not undeclared-function calls: the
        // macro expands to calls of real, declared functions. The prescan
        // pre-pass collects these definitions cross-file (e.g. curl's
        // `curlx_free`/`curlx_calloc`, defined in `curl_setup.h`), which the
        // per-file `declared_functions` set cannot see. The in-file equivalent
        // is already handled by `track_function_declaration`.
        for macro_name in context.function_macros.keys() {
            funcs.insert(macro_name.clone());
        }
        *self.cross_file_functions.borrow_mut() = funcs;
        *self.cross_file_macro_names.borrow_mut() = context.defined_macro_names.clone();
        // A project header that resolves to a directory we can see but a file
        // that isn't there is generated by a build step (seL4 emits its whole
        // bitfield accessor API — `pte_new`, `cap_get_capType`,
        // `cap_frame_cap_get_capFIsDevice`, ~130 names — into
        // `<object/structures_gen.h>` from an `.bf` spec). Every declaration
        // in it is invisible to us, so the undeclared-call check has no sound
        // basis anywhere in this project and is switched off; the
        // missing-type-specifier and implicit-return-type checks, which only
        // read declarations we *can* see, keep running (task 580).
        *self.incomplete_declarations.borrow_mut() = !context.unresolved_project_headers.is_empty();
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }
}

/// Returns true if the name looks like a C macro rather than a function.
///
/// By C convention, macro names are ALL_CAPS (may include digits and underscores).
/// Tree-sitter sees macro invocations like `SAFE_PRINT(x)` as function calls
/// because it cannot expand preprocessor definitions. Skipping all-uppercase
/// names avoids these false positives.
fn is_macro_like_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Names of function-pointer-typed parameters declared by `func_node`'s own
/// parameter list (e.g. `xToken` in `int (*xToken)(void*, int, ...)`).
/// Does not descend into a parameter's own declarator subtree beyond what's
/// needed to find its identifier, so a parameter that is itself a
/// function-pointer-returning-function-pointer still resolves to one name,
/// and a *nested* function pointer's own (unrelated) parameter list is never
/// mistaken for `func_node`'s.
fn function_pointer_param_names(func_node: &Node, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    let Some(func_declarator) = func_node
        .child_by_field_name("declarator")
        .and_then(|d| unwrap_to_function_declarator(&d))
    else {
        return names;
    };
    let Some(param_list) = func_declarator.child_by_field_name("parameters") else {
        return names;
    };
    for i in 0..param_list.child_count() {
        let Some(param) = param_list.child(i) else {
            continue;
        };
        if param.kind() != "parameter_declaration" {
            continue;
        }
        for j in 0..param.child_count() {
            let Some(child) = param.child(j) else {
                continue;
            };
            if matches!(
                child.kind(),
                "pointer_declarator" | "array_declarator" | "function_declarator"
            ) && declarator_utils::is_function_declarator(&child)
            {
                if let Some(name) = ast_utils::find_identifier_in_declarator(&child, source) {
                    names.push(name);
                }
            }
        }
    }
    names
}

/// Find a function's own `function_declarator` (the one carrying its
/// parameter list), skipping through a pointer-return-type wrapper
/// (`char *foo(...)` parses as `pointer_declarator(function_declarator)`).
fn unwrap_to_function_declarator<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    match node.kind() {
        "function_declarator" => Some(*node),
        "pointer_declarator" => node
            .child_by_field_name("declarator")
            .and_then(|d| unwrap_to_function_declarator(&d)),
        _ => None,
    }
}

/// Returns true if the node is nested inside a preprocessor conditional block
/// (#ifdef, #ifndef, #if, #elif). Calls inside these blocks may reference
/// functions declared in conditionally-included headers that tree-sitter
/// cannot resolve.
fn is_inside_preproc_conditional(node: &Node) -> bool {
    let mut current = *node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "preproc_ifdef" | "preproc_if" | "preproc_elif" => return true,
            _ => {}
        }
        current = parent;
    }
    false
}
