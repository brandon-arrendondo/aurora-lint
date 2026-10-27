// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

// DCL20-C: Explicitly specify void when a function accepts no arguments
//
// This rule detects function declarations and definitions that have empty
// parameter lists () instead of explicit (void), which in C means the function
// can accept any number of arguments (not checked by compiler).
//
// Detection strategy:
// 1. Find all function declarations and definitions
// 2. Check if parameter list is empty ()
// 3. Flag violations and suggest using (void)
//
// A statement that opens with a function-like macro invocation, `CHECK(a)
// act();`, parses as a declaration whose type is the invocation. When the
// macro expands to a statement (`#define CHECK(x) if (x)`), the statement is
// a call, not a declaration of `act`, and is not reported.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::analyze::macro_expand::{self, FunctionMacro};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::node_children::NodeChildren;
use crate::utility::cert_c::pp_tokens::{lex_replacement_list, PpKind};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use tree_sitter::Node;

/// Keywords that begin a statement and never a declaration (C11 6.8).
const STATEMENT_KEYWORDS: &[&str] = &[
    "if", "else", "for", "while", "do", "switch", "return", "goto", "break", "continue", "case",
    "default",
];

/// How deep a chain of macros each beginning with the next is followed.
const MAX_MACRO_DEPTH: usize = 8;

#[derive(Default)]
pub struct Dcl20C {
    /// The project's function-like macros, from the prescan.
    function_macros: RefCell<Arc<HashMap<String, FunctionMacro>>>,
}

/// The function-like macros a file can see: the project's, and the file's
/// own, collected once on the first declaration that needs them.
struct Macros<'p> {
    project: &'p HashMap<String, FunctionMacro>,
    local: Option<HashMap<String, FunctionMacro>>,
}

impl Macros<'_> {
    fn get(&mut self, name: &str, root: &Node, source: &str) -> Option<FunctionMacro> {
        let local = self
            .local
            .get_or_insert_with(|| macro_expand::collect_function_macros(root, source));
        local.get(name).or_else(|| self.project.get(name)).cloned()
    }
}

impl Dcl20C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check a node and all its descendants for violations
    fn check_node<'a>(
        &self,
        node: &Node<'a>,
        root: &Node<'a>,
        source: &'a str,
        macros: &mut Macros,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Only check function declarations (prototypes), NOT definitions.
        // In C, f() in a definition already means "no arguments" and is
        // just a style concern. In a declaration/prototype, f() means
        // "unspecified arguments" which is the actual semantic issue.
        if node.kind() == "declaration" && !heads_a_statement(node, root, source, macros) {
            // Look for function declarators in the declaration
            self.check_declaration_for_function(&node, source, violations);
        }

        // Recurse into children
        for child in node.child_nodes() {
            self.check_node(&child, root, source, macros, violations);
        }
    }

    /// Check a function declarator for empty parameter list
    fn check_function_declarator<'a>(
        &self,
        declarator: &Node<'a>,
        source: &'a str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Find the function_declarator node
        if declarator.kind() == "function_declarator" {
            if let Some(params) = declarator.child_by_field_name("parameters") {
                // Check if parameter list is empty or has no void
                if self.has_empty_parameters(&params, source) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        line: params.start_position().row + 1,
                        column: params.start_position().column + 1,
                        message: "Function has empty parameter list () - should explicitly specify (void) to indicate no arguments".to_string(),
                        severity: self.severity(),
                        file_path: String::new(),
                        suggestion: Some("Change () to (void) to explicitly indicate function takes no arguments".to_string()),
                        requires_manual_review: None,
                    });
                }
            }
            // The declarator inside it may be a function declarator of its
            // own: `int (*getf())(void);` declares `getf()`, returning a
            // pointer to a function taking `(void)`.
            if let Some(inner) = declarator.child_by_field_name("declarator") {
                self.check_function_declarator(&inner, source, violations);
            }
        } else {
            // Recurse to find function_declarator
            for child in declarator.child_nodes() {
                self.check_function_declarator(&child, source, violations);
            }
        }
    }

    /// Check declaration for function declarators
    fn check_declaration_for_function<'a>(
        &self,
        decl: &Node<'a>,
        source: &'a str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Every declarator of the declaration, whatever wraps its function
        // declarator: `char *f();` is a pointer_declarator, `char *(*fp)();`
        // a pointer_declarator around a parenthesized one, and `int x = 0` an
        // init_declarator. The type specifiers are not declarators.
        let mut cursor = decl.walk();
        for child in decl.children_by_field_name("declarator", &mut cursor) {
            self.check_function_declarator(&child, source, violations);
        }
    }

    /// Check if parameter list is empty (no void)
    fn has_empty_parameters<'a>(&self, params: &Node<'a>, source: &'a str) -> bool {
        let params_text = get_node_text(params, source).trim();

        // Check if it's literally just ()
        if params_text == "()" {
            return true;
        }

        // Check if there are any parameter_declaration children
        let mut has_params = false;
        for child in params.child_nodes() {
            if child.kind() == "parameter_declaration" {
                has_params = true;
                // Check if it's a void parameter
                let param_text = get_node_text(&child, source).trim();
                if param_text == "void" {
                    return false; // Has explicit void, no violation
                }
            } else if child.kind() == "type_identifier" {
                // Direct type identifier child
                let type_text = get_node_text(&child, source).trim();
                if type_text == "void" {
                    return false; // Has explicit void
                }
            }
        }

        // If no parameters found and not explicitly void, it's a violation
        if !has_params {
            // Double check the text doesn't contain void
            return !params_text.contains("void");
        }

        false
    }
}

impl CertRule for Dcl20C {
    fn rule_id(&self) -> &'static str {
        "DCL20-C"
    }

    fn description(&self) -> &'static str {
        "Explicitly specify void when a function accepts no arguments"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "DCL20-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.function_macros.borrow_mut() = Arc::clone(&context.function_macros);
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let project = Arc::clone(&self.function_macros.borrow());
        let mut macros = Macros {
            project: &project,
            local: None,
        };
        self.check_node(node, node, source, &mut macros, violations);
    }
}

/// Whether `decl` is a statement that opens with a macro invocation tree-sitter
/// read as its type: `CHECK(a) act();` with `#define CHECK(x) if (x)`. Its
/// "declarator" is then the call the expanded statement makes.
fn heads_a_statement(decl: &Node, root: &Node, source: &str, macros: &mut Macros) -> bool {
    let Some(name) = decl
        .child_by_field_name("type")
        .filter(|t| t.kind() == "macro_type_specifier")
        .and_then(|t| t.child_by_field_name("name"))
    else {
        return false;
    };
    macro_begins_statement(get_node_text(&name, source), root, source, macros, 0)
}

/// Whether every live definition of the function-like macro `name` begins
/// with a statement keyword, directly or through another such macro. A name
/// with no visible definition, or a definition the expander cannot read, is
/// not one.
fn macro_begins_statement(
    name: &str,
    root: &Node,
    source: &str,
    macros: &mut Macros,
    depth: usize,
) -> bool {
    let Some(definition) = macros.get(name, root, source) else {
        return false;
    };
    let definitions: Vec<Option<FunctionMacro>> = if definition.alternatives.is_empty() {
        vec![Some(definition)]
    } else {
        definition.alternatives
    };
    definitions.iter().all(|d| {
        d.as_ref().is_some_and(|d| {
            let tokens = lex_replacement_list(&d.body, true);
            let Some(first) = tokens.first().filter(|t| t.kind == PpKind::Identifier) else {
                return false;
            };
            if d.params.iter().any(|p| *p == first.text) {
                return false;
            }
            STATEMENT_KEYWORDS.contains(&first.text.as_ref())
                || (depth < MAX_MACRO_DEPTH
                    && tokens.get(1).is_some_and(|t| t.text == "(")
                    && macro_begins_statement(&first.text, root, source, macros, depth + 1))
        })
    })
}
