// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! MSC37-C: Ensure that control never reaches the end of a non-void function
//!
//! This rule addresses undefined behavior that occurs when a non-void function
//! completes without executing a return statement. If control reaches the closing
//! brace of a non-void function without evaluating a return statement, using the
//! return value is undefined behavior.
//!
//! ## Non-compliant examples:
//!
//! **Missing return statement:**
//! ```c
//! int get_value(void) {
//!     // No return statement - undefined behavior
//! }
//! ```
//!
//! **Return missing in some paths:**
//! ```c
//! int check_password(const char *password) {
//!     if (strcmp(password, "secret") == 0) {
//!         return 1;  // Match
//!     }
//!     // No return for mismatch case - undefined behavior
//! }
//! ```
//!
//! ## Compliant solutions:
//!
//! **Add explicit return:**
//! ```c
//! int get_value(void) {
//!     return 42;
//! }
//! ```
//!
//! **Return on all paths:**
//! ```c
//! int check_password(const char *password) {
//!     if (strcmp(password, "secret") == 0) {
//!         return 1;  // Match
//!     }
//!     return 0;  // No match
//! }
//! ```
//!
//! **Exception - a hosted `int main()` implicitly returns 0 (EX1):**
//! ```c
//! int main(void) {
//!     printf("Hello World\n");
//!     // Implicitly returns 0 - compliant per C standard
//! }
//! ```
//!
//! A `main` that is not `int main` in a hosted environment returns nothing
//! implicitly, so it is checked like any other function.
//!
//! ## What ends a path without a `return`
//!
//! - a call to a function trusted not to return (`_Noreturn`, `exit`, ...; the
//!   `trust_noreturn_keyword` option), never a wrapper that merely calls one;
//! - a call to a function declared noreturn by a GNU attribute, directly or
//!   through a macro defined as one, or to a function-like macro whose every
//!   definition is such a call (the default preset; the
//!   `msc37_attribute_noreturn` option);
//! - a call to C23 `unreachable()`, only when the C23 edition is declared
//!   (`c_standard`) and the file defines no `unreachable` of its own;
//! - a loop with a constant-true condition and no `break` or `goto` out of it;
//! - a `switch` with a `default`, no `break` out of it, and a last arm that
//!   ends this way.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::{IncludeClosure, ProjectContext};
use crate::analyze::macro_expand::{collect_function_macro_alternatives, ProjectMacroArm};
use crate::manifest::Severity;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

pub struct Msc37C {
    /// Function-like macros the prescan collected project-wide, so a
    /// `RETURN`-style macro defined in a header is known when a file's
    /// function ends with it.
    project_function_macros: RefCell<Arc<HashMap<String, Vec<ProjectMacroArm>>>>,
    /// The include graph: a project macro defined in a file this one cannot
    /// include is not a definition here (ADR-0006).
    include_edges: RefCell<Arc<HashMap<String, Vec<String>>>>,
    /// Functions the project declares noreturn by GNU attribute, and the
    /// macros defined as that attribute, for `msc37_attribute_noreturn`.
    attribute_functions: RefCell<Arc<HashSet<String>>>,
    attribute_macros: RefCell<Arc<HashSet<String>>>,
    /// The same for an ISO spelling reached through a macro (`#define NR
    /// [[noreturn]]`), which every preset credits.
    keyword_functions: RefCell<Arc<HashSet<String>>>,
    keyword_macros: RefCell<Arc<HashSet<String>>>,
    /// Function-like macros that return only on some path
    /// (`CHECK(x)` is `if (!(x)) return -1;`). A call ends the function's
    /// path for the check that a function returns, but a `break` after one
    /// is still reachable.
    sometimes_returning: RefCell<HashSet<String>>,
    /// `macro_body_always_returns` by body text: it parses the body, and the
    /// same macro is met in file after file.
    always_returns_memo: RefCell<HashMap<String, bool>>,
    /// The run's policy and environment settings: whether a `_Noreturn`
    /// declaration is trusted (`trust_noreturn_keyword`).
    settings: RefCell<Arc<AnalysisSettings>>,
    /// `typedef name -> aliased type text` as this file sees it, so a
    /// function returning `VOID` (`typedef void VOID;`) is a void function.
    typedefs: RefCell<Arc<HashMap<String, String>>>,
    /// The file being checked, for the edition a compile database declares
    /// for it.
    file_path: RefCell<String>,
}

impl Msc37C {
    pub fn new() -> Self {
        Self {
            project_function_macros: RefCell::default(),
            include_edges: RefCell::default(),
            always_returns_memo: RefCell::default(),
            attribute_functions: RefCell::default(),
            attribute_macros: RefCell::default(),
            keyword_functions: RefCell::default(),
            keyword_macros: RefCell::default(),
            sometimes_returning: RefCell::default(),
            settings: RefCell::default(),
            typedefs: RefCell::default(),
            file_path: RefCell::default(),
        }
    }

    /// Whether the C23 edition is declared for this file: by the
    /// configuration, which wins, or by the compile database's entry for it.
    /// Undeclared is read strictly (C11), where `unreachable()` is no macro
    /// of the standard library.
    fn c23_declared(&self) -> bool {
        let settings = self.settings.borrow();
        let declared = settings.c_standard.or_else(|| {
            settings
                .compile_facts
                .of(&self.file_path.borrow())
                .and_then(|facts| facts.c_standard)
        });
        declared.is_some_and(|edition| edition >= crate::settings::CStandard::C23)
    }

    /// Whether the function returns `void`: the type specifier is `void`
    /// (directly, through a macro that precedes it, or through a typedef) and
    /// the declarator adds no pointer. `void *f()` returns a value.
    fn returns_void(&self, func_def: &Node, type_node: &Node, source: &str) -> bool {
        if declarator_returns_pointer(func_def.child_by_field_name("declarator")) {
            return false;
        }
        if self.is_void_type(type_node, source) || self.has_void_specifier(func_def, source) {
            return true;
        }
        type_node.kind() == "type_identifier"
            && crate::utility::cert_c::overflow_helpers::resolve_typedef_chain(
                get_node_text(type_node, source).trim(),
                &self.typedefs.borrow(),
            ) == "void"
    }

    /// Function-like macros whose replacement list contains a `return`:
    /// `MBEDTLS_MPS_TRACE_RETURN(val)` is how every function in mbedtls's
    /// mps_reader.c returns, and the body shows no `return_statement` at
    /// all. A call to one is a return for this rule's purposes.
    /// This file's own definitions first, then the project's.
    ///
    /// Second, of those, the ones that return on only some path
    /// (`if (!(x)) return -1;`): a definition that does not return on every
    /// path, or another arm that has no `return` at all.
    fn returning_macros(
        &self,
        bodies: &HashMap<String, Vec<String>>,
    ) -> (HashSet<String>, HashSet<String>) {
        fn returns(body: &str) -> bool {
            body.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .any(|tok| tok == "return")
        }
        let returning: HashSet<String> = bodies
            .iter()
            .filter(|(_, defs)| defs.iter().any(|b| returns(b)))
            .map(|(name, _)| name.clone())
            .collect();
        let sometimes = returning
            .iter()
            .filter(|name| !bodies[*name].iter().all(|b| self.always_returns(b)))
            .cloned()
            .collect();
        (returning, sometimes)
    }

    fn always_returns(&self, body: &str) -> bool {
        if let Some(known) = self.always_returns_memo.borrow().get(body) {
            return *known;
        }
        let known = macro_body_always_returns(body);
        self.always_returns_memo
            .borrow_mut()
            .insert(body.to_string(), known);
        known
    }

    /// Every live definition of each function-like macro the file sees, as
    /// replacement-list text: its own (any arm), the project's from any
    /// header, and the project's from the `.c` files it may include. A macro
    /// another `.c` file keeps private defines nothing in this file.
    fn visible_macro_bodies(&self, source: &str) -> HashMap<String, Vec<String>> {
        let mut bodies: HashMap<String, Vec<String>> = HashMap::new();
        for (name, alts) in collect_function_macro_alternatives(source) {
            bodies
                .entry(name)
                .or_default()
                .extend(alts.into_iter().map(|m| m.body));
        }
        // A macro a header defines counts whether or not the closure reaches
        // the header: the closure is a lower bound, since a header that
        // includes a generated one the scan cannot read hides what follows
        // (seL4's `fail()` wrapper is reached that way). Only a `.c` file's
        // macro, which no other file includes, is scoped by the closure.
        let closure = IncludeClosure::of_scan(
            &self.include_edges.borrow(),
            std::path::Path::new(&*self.file_path.borrow()),
        );
        for (name, entries) in self.project_function_macros.borrow().iter() {
            for e in entries.iter().filter(|e| {
                e.files
                    .iter()
                    .any(|f| !crate::files::is_c_translation_unit(f) || closure.may_include(f))
            }) {
                bodies
                    .entry(name.clone())
                    .or_default()
                    .push(e.arm.body.clone());
            }
        }
        bodies
    }

    /// The functions this file's calls reach that are declared noreturn by
    /// GNU attribute (`msc37_attribute_noreturn`), and the function-like
    /// macros whose every definition is one call to such a function.
    ///
    /// A function the file defines `static` is its own, so another file's
    /// same-named attribute declaration does not reach it; the file's own
    /// declarations are read with the project's attribute macros.
    fn attribute_noreturn_names(
        &self,
        root: &Node,
        source: &str,
        bodies: &HashMap<String, Vec<String>>,
    ) -> HashSet<String> {
        use crate::analyze::noreturn as nr;
        let mut macros: HashSet<String> = self.attribute_macros.borrow().as_ref().clone();
        nr::collect_attribute_noreturn_macro_names(source, &mut macros);
        let names = self.declared_through(
            root,
            source,
            &self.attribute_functions.borrow(),
            |candidates| nr::attribute_noreturn_declared_in(candidates, &macros),
        );
        Self::with_wrapping_macros(bodies, names)
    }

    /// The functions this file's calls reach that are declared noreturn by an
    /// ISO spelling written through a macro (`#define NR [[noreturn]]`;
    /// `NR void die(void);`), and the macros that wrap a call to one. The
    /// keyword is credited under every preset, as when written directly.
    fn keyword_noreturn_names(
        &self,
        root: &Node,
        source: &str,
        bodies: &HashMap<String, Vec<String>>,
    ) -> HashSet<String> {
        use crate::analyze::noreturn as nr;
        let mut macros: HashSet<String> = self.keyword_macros.borrow().as_ref().clone();
        nr::collect_keyword_noreturn_macro_names(source, &mut macros);
        let names = self.declared_through(
            root,
            source,
            &self.keyword_functions.borrow(),
            |candidates| nr::keyword_noreturn_declared_in(candidates, &macros),
        );
        Self::with_wrapping_macros(bodies, names)
    }

    /// `project` less the functions this file defines `static`, plus the
    /// file's own declarations that `declared_in` accepts.
    fn declared_through(
        &self,
        root: &Node,
        source: &str,
        project: &HashSet<String>,
        declared_in: impl Fn(&HashMap<String, HashSet<String>>) -> HashSet<String>,
    ) -> HashSet<String> {
        use crate::analyze::noreturn as nr;
        let mut own_statics = HashSet::new();
        crate::analyze::prescan::collect_static_function_names(root, source, &mut own_statics);
        let mut names: HashSet<String> = project.difference(&own_statics).cloned().collect();
        names.extend(declared_in(&nr::collect_attribute_candidates(
            root,
            source,
            &nr::raw_text_or(&self.file_path.borrow(), source),
        )));
        names
    }

    /// `names` plus every function-like macro whose every live definition
    /// (`bodies`) is one call to a function in `names`.
    fn with_wrapping_macros(
        bodies: &HashMap<String, Vec<String>>,
        mut names: HashSet<String>,
    ) -> HashSet<String> {
        let credited: Vec<String> = bodies
            .iter()
            .filter(|(_, defs)| {
                !defs.is_empty()
                    && defs
                        .iter()
                        .all(|d| single_call_callee(d).is_some_and(|c| names.contains(c)))
            })
            .map(|(name, _)| name.clone())
            .collect();
        names.extend(credited);
        names
    }

    /// Whether the function body returns anywhere: a `return_statement`, or
    /// a call to a macro that returns.
    fn has_return(&self, body: &Node, source: &str, returning_macros: &HashSet<String>) -> bool {
        if self.has_return_statement(body) {
            return true;
        }
        !returning_macros.is_empty()
            && query::find_first_descendant(*body, |n| {
                n.kind() == "call_expression"
                    && n.child_by_field_name("function")
                        .is_some_and(|f| returning_macros.contains(get_node_text(&f, source)))
            })
            .is_some()
    }

    /// Check if a type is void
    fn is_void_type(&self, type_node: &Node, source: &str) -> bool {
        let type_text = get_node_text(type_node, source);
        type_text.trim() == "void"
    }

    /// Check if any direct child of function_definition is "void".
    /// Handles cases like `MACRO void func()` where a macro precedes void and
    /// tree-sitter assigns the macro as the type field. The actual "void" keyword
    /// ends up in an ERROR node since tree-sitter doesn't expect two type specifiers.
    fn has_void_specifier(&self, func_def: &Node, source: &str) -> bool {
        for i in 0..func_def.child_count() {
            if let Some(child) = func_def.child(i) {
                if get_node_text(&child, source).trim() == "void" {
                    return true;
                }
            }
        }
        false
    }

    /// Check if a function is main()
    fn is_main_function(&self, declarator: &Node, source: &str) -> bool {
        // Look for function_declarator with name "main"
        if let Some(func_declarator) = self.find_function_declarator(declarator) {
            if let Some(name_node) = func_declarator.child_by_field_name("declarator") {
                let name = get_node_text(&name_node, source);
                return name.trim() == "main";
            }
        }
        false
    }

    /// Find function_declarator node in declarator tree
    fn find_function_declarator<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        if node.kind() == "function_declarator" {
            return Some(*node);
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(found) = self.find_function_declarator(&child) {
                    return Some(found);
                }
            }
        }
        None
    }

    /// Check if function body contains any return statement
    fn has_return_statement(&self, node: &Node) -> bool {
        query::find_first_descendant(*node, |n| n.kind() == "return_statement").is_some()
    }

    /// Collect names of functions declared or defined `_Noreturn` anywhere
    /// in the translation unit, so a trailing call to one of them can be
    /// recognized as equivalent to a return (MSC37-C's own compliant
    /// example: a switch covering all enum values followed by a call to a
    /// `_Noreturn` fallback function, with no return after it).
    fn collect_noreturn_function_names(root: &Node, source: &str) -> HashSet<String> {
        let mut names = HashSet::new();
        for node in query::find_descendants_of_kinds(*root, &["declaration", "function_definition"])
        {
            if !crate::analyze::noreturn::has_noreturn_keyword(&node, source) {
                continue;
            }
            if let Some(declarator) = node.child_by_field_name("declarator") {
                if let Some(func_declarator) = Self::find_function_declarator_static(&declarator) {
                    if let Some(name_node) = func_declarator.child_by_field_name("declarator") {
                        names.insert(get_node_text(&name_node, source).trim().to_string());
                    }
                }
            }
        }
        names
    }

    /// Non-method variant of `find_function_declarator` (needed in a
    /// static/associated-function context above).
    fn find_function_declarator_static<'a>(node: &Node<'a>) -> Option<Node<'a>> {
        if node.kind() == "function_declarator" {
            return Some(*node);
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(found) = Self::find_function_declarator_static(&child) {
                    return Some(found);
                }
            }
        }
        None
    }

    /// True if `node` is an `expression_statement` wrapping a call to a
    /// known-noreturn function (stdlib or `_Noreturn`-declared in this
    /// file).
    fn is_noreturn_call_statement(
        &self,
        node: &Node,
        source: &str,
        noreturn_names: &HashSet<String>,
    ) -> bool {
        if node.kind() != "expression_statement" {
            return false;
        }
        let Some(call) = node.child(0).filter(|c| c.kind() == "call_expression") else {
            return false;
        };
        // A standard noreturn function satisfies MSC37-C the same way an
        // explicit return would, when the environment honors that contract.
        // Either way the callee must name the function itself, not a
        // pointer or a file's own definition spelled the same.
        crate::analyze::noreturn::calls_stdlib_noreturn(
            &call,
            source,
            Some(&self.settings.borrow()),
        ) || crate::analyze::noreturn::calls_noreturn(&call, source, noreturn_names)
    }

    /// Whether `node` is a call statement after which control does not reach
    /// the next statement: [`Self::is_noreturn_call_statement`], less a macro
    /// that returns only on some path.
    fn is_jump_statement(
        &self,
        node: &Node,
        source: &str,
        noreturn_names: &HashSet<String>,
    ) -> bool {
        if !self.is_noreturn_call_statement(node, source, noreturn_names) {
            return false;
        }
        let sometimes = self.sometimes_returning.borrow();
        node.child(0)
            .and_then(|call| crate::analyze::noreturn::called_function_name(&call, source))
            .is_none_or(|name| !sometimes.contains(&name))
    }

    /// Check if the last statement in a compound statement is a return
    /// (possibly through nested if/switch branches that all return).
    ///
    /// `ends_with_return`/`all_branches_return`/`statement_returns` used to
    /// be three mutually recursive functions chaining through nested
    /// if/else-if and compound-statement nesting -- a long else-if chain
    /// would cost one native call frame per link (the same hostap-style
    /// risk class as the original ARR00-C/MEM33-C bug). They're
    /// unified here into one postorder evaluator using an explicit
    /// instruction/value stack instead of recursion: `if_statement` needs
    /// BOTH its consequence and alternative evaluated before it can AND
    /// them together, so this uses the classic stack-machine technique
    /// (push `Eval` work, push an `And` combinator that pops two already-
    /// computed results) rather than a plain node-only stack.
    fn ends_with_return(
        &self,
        compound_stmt: &Node,
        source: &str,
        noreturn_names: &HashSet<String>,
    ) -> bool {
        self.stmt_returns(compound_stmt, source, noreturn_names)
    }

    fn stmt_returns(&self, root: &Node, source: &str, noreturn_names: &HashSet<String>) -> bool {
        let mut ops: Vec<Op> = vec![Op::Eval(*root)];
        let mut values: Vec<bool> = Vec::new();

        while let Some(op) = ops.pop() {
            match op {
                Op::Eval(node) => match node.kind() {
                    "return_statement" => values.push(true),
                    // The last statement of an `else` or a `case` arm that is
                    // itself a call that does not return.
                    "expression_statement" => {
                        values.push(self.is_noreturn_call_statement(&node, source, noreturn_names))
                    }
                    "while_statement" | "for_statement" | "do_statement" => {
                        values.push(loop_never_falls_through(&node, source, &|n: &Node| {
                            self.is_jump_statement(n, source, noreturn_names)
                        }));
                    }
                    // A `goto` back to a label above it (`goto retry;`) runs
                    // that code again instead of reaching the end; one that
                    // jumps forward may land anywhere.
                    "goto_statement" => values.push(goto_goes_back(&node, source)),
                    "compound_statement" => match last_statement_of_block(&node) {
                        Some(stmt)
                            if self.is_noreturn_call_statement(&stmt, source, noreturn_names) =>
                        {
                            values.push(true);
                        }
                        Some(stmt) => ops.push(Op::Eval(stmt)),
                        None => values.push(false),
                    },
                    "if_statement" => {
                        // Must have both consequence and alternative, both returning
                        match (
                            node.child_by_field_name("consequence"),
                            node.child_by_field_name("alternative"),
                        ) {
                            (Some(consequence), Some(alternative)) => {
                                ops.push(Op::And);
                                ops.push(Op::Eval(alternative));
                                ops.push(Op::Eval(consequence));
                            }
                            _ => values.push(false),
                        }
                    }
                    "switch_statement" => match switch_last_arm_tail(&node, source, &|n: &Node| {
                        self.is_jump_statement(n, source, noreturn_names)
                    }) {
                        Some(tail) => ops.push(Op::Eval(tail)),
                        None => values.push(false),
                    },
                    // `cleanup: return ret;` -- the label's own statement
                    // is its last named child, and it is what runs last.
                    "labeled_statement" => {
                        match node.named_child(node.named_child_count().saturating_sub(1)) {
                            Some(inner) if inner.kind() != "statement_identifier" => {
                                ops.push(Op::Eval(inner));
                            }
                            _ => values.push(false),
                        }
                    }
                    // A function whose tail is `#if X ... return 0; #endif`
                    // or an `#if`/`#else` pair whose arms both return does
                    // return under every configuration it is written for
                    // (mbedtls aes.c). Each arm is the last
                    // statement of that arm; an `#if` with no `#else` is
                    // judged on the arm the author wrote.
                    "preproc_if" | "preproc_ifdef" | "preproc_elif" | "preproc_else" => {
                        match preproc_arm_tail(&node, source) {
                            ArmTail::Both(stmt, alt) => {
                                ops.push(Op::And);
                                ops.push(Op::Eval(alt));
                                ops.push(Op::Eval(stmt));
                            }
                            ArmTail::One(stmt) => ops.push(Op::Eval(stmt)),
                            ArmTail::Returns => values.push(true),
                            ArmTail::Empty => values.push(false),
                        }
                    }
                    "else_clause" => {
                        // else_clause wraps the actual statement (compound_statement or single stmt)
                        let inner = (0..node.child_count())
                            .filter_map(|i| node.child(i))
                            .find(|child| child.kind() != "else" && child.kind() != "comment");
                        match inner {
                            Some(child) => ops.push(Op::Eval(child)),
                            None => values.push(false),
                        }
                    }
                    _ => values.push(false),
                },
                Op::And => {
                    let b = values.pop().unwrap_or(false);
                    let a = values.pop().unwrap_or(false);
                    values.push(a && b);
                }
            }
        }

        values.pop().unwrap_or(false)
    }

    /// Check a function definition for missing returns
    fn check_function_definition(
        &self,
        node: &Node,
        source: &str,
        noreturn_names: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() != "function_definition" {
            return;
        }

        // Get return type
        let type_node = match node.child_by_field_name("type") {
            Some(n) => n,
            None => return,
        };

        // Skip void functions — also check for void as a sibling specifier
        // to handle macros preceding void (e.g., STATIC void func())
        if self.returns_void(node, &type_node, source) {
            return;
        }

        // Skip phantom "functions" from preprocessor-broken else-if chains.
        // When `else if (...)` appears inside #ifdef with no preceding `if` in
        // the same scope, tree-sitter may misparse it as a function definition
        // with "else" as the type specifier.
        let type_text = get_node_text(&type_node, source);
        let type_trimmed = type_text.trim();
        if matches!(
            type_trimmed,
            "else" | "if" | "while" | "for" | "do" | "switch" | "case" | "default" | "return"
        ) {
            return;
        }

        // Get declarator
        let declarator = match node.child_by_field_name("declarator") {
            Some(d) => d,
            None => return,
        };

        // EX1: a hosted `int main` returns 0 when it reaches its closing brace
        // (C11 5.1.2.2.3). A freestanding `main`, or one of another return
        // type, has no such rule.
        if self.is_main_function(&declarator, source)
            && type_trimmed == "int"
            && self.settings.borrow().environment == crate::settings::EnvironmentKind::Hosted
        {
            return;
        }

        // Get function body
        let body = match node.child_by_field_name("body") {
            Some(b) => b,
            None => return,
        };

        // A body that ends every path with a return, a call that does not
        // return, or a loop nothing leaves is complete, whatever it contains.
        if self.ends_with_return(&body, source, noreturn_names) {
            return;
        }
        let (message, suggestion) = if self.has_return(&body, source, noreturn_names) {
            (
                "Non-void function may reach end without returning a value. Ensure all execution paths have explicit return statements.",
                "Add return statements to ensure all execution paths return a value",
            )
        } else {
            (
                "Non-void function has no return statement. Control reaching the end of a non-void function without returning a value is undefined behavior.",
                "Add a return statement on all execution paths of this function",
            )
        };
        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: self.severity(),
            message: message.to_string(),
            file_path: String::new(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            suggestion: Some(suggestion.to_string()),
            ..Default::default()
        });
    }
}

/// Work item for `stmt_returns`'s explicit evaluation stack.
enum Op<'a> {
    Eval(Node<'a>),
    And,
}

/// What a preprocessor arm contributes to `stmt_returns`.
enum ArmTail<'a> {
    /// `#if` arm's last statement and an `#else`/`#elif` to AND with.
    Both(Node<'a>, Node<'a>),
    /// A bare `#if` (or the final `#else`): its own last statement.
    One(Node<'a>),
    /// An `#error` arm with nothing else: that configuration cannot be
    /// the built one, so it does not fall off the end.
    Returns,
    /// No statement at all.
    Empty,
}

/// The last statement of a compound statement, ignoring braces, comments
/// and bare directives, and ignoring a conditional block that holds no
/// statement (only directives/comments after the real last statement).
fn last_statement_of_block<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    let mut last_stmt = None;
    for i in 0..node.child_count() {
        let Some(child) = node.child(i) else { continue };
        let kind = child.kind();
        if matches!(
            kind,
            "{" | "}"
                | "comment"
                | "preproc_def"
                | "preproc_function_def"
                | "preproc_include"
                | "preproc_call"
        ) {
            continue;
        }
        if kind.starts_with("preproc_") && !has_statement_child(&child) {
            continue;
        }
        last_stmt = Some(child);
    }
    last_stmt
}

/// The tail of one preprocessor arm: its last statement (skipping the
/// condition, comments and bare directives) and its `#else`/`#elif`.
fn preproc_arm_tail<'a>(node: &Node<'a>, source: &str) -> ArmTail<'a> {
    let condition = node.child_by_field_name("condition");
    let mut last_stmt = None;
    let mut alternative = None;
    for i in 0..node.named_child_count() {
        let Some(child) = node.named_child(i) else {
            continue;
        };
        if Some(child) == condition {
            continue;
        }
        match child.kind() {
            "preproc_else" | "preproc_elif" => alternative = Some(child),
            "comment"
            | "preproc_call"
            | "preproc_def"
            | "preproc_function_def"
            | "preproc_include" => {}
            _ => last_stmt = Some(child),
        }
    }
    match (last_stmt, alternative) {
        (Some(stmt), Some(alt)) => ArmTail::Both(stmt, alt),
        (Some(stmt), None) => ArmTail::One(stmt),
        (None, Some(alt)) if is_error_directive_arm(node, source) => ArmTail::One(alt),
        (None, None) if is_error_directive_arm(node, source) => ArmTail::Returns,
        (None, _) => ArmTail::Empty,
    }
}

/// Whether this preprocessor arm's own content is an `#error` directive.
fn is_error_directive_arm(node: &Node, source: &str) -> bool {
    (0..node.named_child_count())
        .filter_map(|i| node.named_child(i))
        .any(|c| {
            c.kind() == "preproc_call"
                && c.child_by_field_name("directive")
                    .is_some_and(|d| get_node_text(&d, source) == "#error")
        })
}

/// Whether a conditional preprocessor block holds at least one statement
/// (directly or in an `#else`/`#elif` arm), as opposed to only directives
/// and comments after the function's real last statement.
fn has_statement_child(node: &Node) -> bool {
    (0..node.named_child_count())
        .filter_map(|i| node.named_child(i))
        .any(|c| {
            (c.kind().ends_with("_statement") || c.kind() == "declaration")
                || (matches!(c.kind(), "preproc_else" | "preproc_elif") && has_statement_child(&c))
        })
}

/// Whether the declarator of a function definition makes it return a pointer
/// (`void *f(void)`, `char **g(void)`): a pointer declarator wraps the
/// function declarator.
fn declarator_returns_pointer(declarator: Option<Node>) -> bool {
    let mut current = declarator;
    while let Some(d) = current {
        match d.kind() {
            "pointer_declarator" => return true,
            "function_declarator" | "parenthesized_declarator" => {
                current = d.child_by_field_name("declarator");
            }
            _ => return false,
        }
    }
    false
}

/// Whether the translation unit declares or defines a function, or defines a
/// macro, called `name`.
fn defines_name(root: &Node, source: &str, name: &str) -> bool {
    query::find_first_descendant(*root, |n| match n.kind() {
        "function_declarator" => n
            .child_by_field_name("declarator")
            .is_some_and(|d| get_node_text(&d, source) == name),
        "preproc_def" | "preproc_function_def" => n
            .child_by_field_name("name")
            .is_some_and(|d| get_node_text(&d, source) == name),
        _ => false,
    })
    .is_some()
}

/// A loop whose condition is a nonzero constant (`while (1)`, `for (;;)`,
/// `do ... while (true)`) and that nothing leaves except a `return` (or a
/// call that does not return): control never reaches the end after it.
fn loop_never_falls_through(node: &Node, source: &str, jumps: &dyn Fn(&Node) -> bool) -> bool {
    let condition = match node.kind() {
        "for_statement" => node.child_by_field_name("condition"),
        _ => match node.child_by_field_name("condition") {
            Some(c) => Some(c),
            None => return false,
        },
    };
    let constant_true = match condition {
        None => node.kind() == "for_statement", // `for (;;)`
        Some(c) => is_constant_true(&c, source),
    };
    if !constant_true {
        return false;
    }
    let Some(body) = node.child_by_field_name("body") else {
        return false;
    };
    !leaves_other_than_by_return(node, &body, source, jumps)
}

fn is_constant_true(condition: &Node, source: &str) -> bool {
    let mut c = *condition;
    while c.kind() == "parenthesized_expression" {
        match c.named_child(0) {
            Some(inner) => c = inner,
            None => return false,
        }
    }
    match c.kind() {
        "true" => true,
        "number_literal" => {
            crate::analyze::const_eval::parse_integer_literal(get_node_text(&c, source))
                .is_some_and(|v| v != 0)
        }
        "identifier" => get_node_text(&c, source) == "true",
        _ => false,
    }
}

/// Whether anything but a `return` takes control out of `construct` (a loop
/// or a switch) to code that can reach the function's end: a `break` aimed at
/// it, or a `goto` to a label after it. A `break` inside a nested loop or
/// switch is aimed at that one; a `break` right after a `return`, `goto`,
/// `continue` or another `break` is dead; a `goto` back to a label before the
/// construct (`goto retry;`) re-enters it rather than leaving for the end.
fn leaves_other_than_by_return(
    construct: &Node,
    body: &Node,
    source: &str,
    jumps: &dyn Fn(&Node) -> bool,
) -> bool {
    let mut stack = vec![*body];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "goto_statement" => {
                if goto_leaves_forward(&node, construct, source) {
                    return true;
                }
                continue;
            }
            "break_statement" => {
                if !is_dead_break(&node, source, jumps) {
                    return true;
                }
                continue;
            }
            "while_statement" | "for_statement" | "do_statement" | "switch_statement" => {
                // A `break` in here belongs to it; a `goto` still leaves.
                for goto in query::find_descendants_of_kind(node, "goto_statement") {
                    if goto_leaves_forward(&goto, construct, source) {
                        return true;
                    }
                }
                continue;
            }
            _ => {}
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    false
}

/// A `break` that nothing reaches: the statement before it (comments aside)
/// always jumps away, as in `return x; break;`, or is a conditional block
/// whose every arm does (`#if A return 1; #else return 2; #endif break;`).
fn is_dead_break(node: &Node, source: &str, jumps: &dyn Fn(&Node) -> bool) -> bool {
    let mut before = node.prev_named_sibling();
    while before.is_some_and(|p| p.kind() == "comment") {
        before = before.and_then(|p| p.prev_named_sibling());
    }
    before.is_some_and(|prev| ends_with_jump(&prev, source, jumps))
}

/// Whether control never continues past `node` to the statement after it.
fn ends_with_jump(node: &Node, source: &str, jumps: &dyn Fn(&Node) -> bool) -> bool {
    match node.kind() {
        "return_statement" | "goto_statement" | "continue_statement" | "break_statement" => true,
        // `abort();` before a `break;` leaves nothing for the break to do.
        "expression_statement" => jumps(node),
        // `{ ...; return x; }` before a `break;`.
        "compound_statement" => {
            last_statement_of_block(node).is_some_and(|last| ends_with_jump(&last, source, jumps))
        }
        // An `if`/`else` chain whose every path jumps.
        "if_statement" => match (
            node.child_by_field_name("consequence"),
            node.child_by_field_name("alternative"),
        ) {
            (Some(c), Some(a)) => {
                ends_with_jump(&c, source, jumps) && ends_with_jump(&a, source, jumps)
            }
            _ => false,
        },
        "else_clause" => node
            .named_child(0)
            .is_some_and(|c| ends_with_jump(&c, source, jumps)),
        "preproc_if" | "preproc_ifdef" | "preproc_elif" | "preproc_else" => {
            match preproc_arm_tail(node, source) {
                ArmTail::Both(stmt, alt) => {
                    ends_with_jump(&stmt, source, jumps) && ends_with_jump(&alt, source, jumps)
                }
                ArmTail::One(stmt) => {
                    matches!(node.kind(), "preproc_else" | "preproc_elif")
                        && ends_with_jump(&stmt, source, jumps)
                }
                ArmTail::Returns => true,
                ArmTail::Empty => false,
            }
        }
        _ => false,
    }
}

/// Whether the `goto` jumps to a label that starts before it.
fn goto_goes_back(goto: &Node, source: &str) -> bool {
    let Some(label) = goto.child_by_field_name("label") else {
        return false;
    };
    let name = get_node_text(&label, source);
    let mut function = *goto;
    while function.kind() != "function_definition" {
        match function.parent() {
            Some(p) => function = p,
            None => return false,
        }
    }
    query::find_descendants_of_kind(function, "labeled_statement")
        .into_iter()
        .any(|l| {
            l.start_byte() < goto.start_byte()
                && l.child_by_field_name("label")
                    .is_some_and(|n| get_node_text(&n, source) == name)
        })
}

/// Whether `goto` jumps to a label after `construct` (or to one the function
/// does not show). A label before it, or inside it, does not take control
/// past the construct.
fn goto_leaves_forward(goto: &Node, construct: &Node, source: &str) -> bool {
    let Some(label) = goto.child_by_field_name("label") else {
        return true;
    };
    let name = get_node_text(&label, source);
    let mut function = *construct;
    while function.kind() != "function_definition" {
        match function.parent() {
            Some(p) => function = p,
            None => return true,
        }
    }
    let target = query::find_descendants_of_kind(function, "labeled_statement")
        .into_iter()
        .find(|l| {
            l.child_by_field_name("label")
                .is_some_and(|n| get_node_text(&n, source) == name)
        });
    match target {
        Some(l) => l.start_byte() >= construct.end_byte(),
        None => true,
    }
}

/// A `switch` falls off its end unless it has a `default`, nothing breaks out
/// of it, and its last arm ends the function. Returns that last arm's final
/// statement to be judged, or `None` when the switch does not qualify.
fn switch_last_arm_tail<'a>(
    node: &Node<'a>,
    source: &str,
    jumps: &dyn Fn(&Node) -> bool,
) -> Option<Node<'a>> {
    let body = node.child_by_field_name("body")?;
    let arms: Vec<Node<'a>> = (0..body.named_child_count())
        .filter_map(|i| body.named_child(i))
        .filter(|c| c.kind() == "case_statement")
        .collect();
    let has_default = arms.iter().any(|arm| {
        get_node_text(arm, source)
            .trim_start()
            .starts_with("default")
    });
    if !has_default || leaves_other_than_by_return(node, &body, source, jumps) {
        return None;
    }
    let last = arms.last()?;
    (0..last.named_child_count())
        .filter_map(|i| last.named_child(i))
        .rfind(|c| match c.kind() {
            "comment" | "preproc_call" => false,
            "break_statement" => !is_dead_break(c, source, jumps),
            _ => true,
        })
        .filter(|c| {
            // The arm's own label value is not a statement.
            c.kind().ends_with("_statement") || c.kind() == "compound_statement"
        })
}

impl CertRule for Msc37C {
    fn reads_header_facts(&self) -> bool {
        true
    }

    fn rule_id(&self) -> &'static str {
        "MSC37-C"
    }

    fn description(&self) -> &'static str {
        "Ensure that control never reaches the end of a non-void function"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "MSC37-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project_function_macros.borrow_mut() = Arc::clone(&context.function_macro_arms);
        *self.include_edges.borrow_mut() = Arc::clone(&context.include_edges);
        *self.attribute_functions.borrow_mut() = Arc::clone(&context.attribute_noreturn_functions);
        *self.attribute_macros.borrow_mut() = Arc::clone(&context.attribute_noreturn_macros);
        *self.keyword_functions.borrow_mut() = Arc::clone(&context.keyword_noreturn_functions);
        *self.keyword_macros.borrow_mut() = Arc::clone(&context.keyword_noreturn_macros);
    }

    fn set_analysis_settings(&self, settings: &Arc<AnalysisSettings>) {
        *self.settings.borrow_mut() = Arc::clone(settings);
    }

    fn set_visible_types(&self, types: &crate::analyze::context::VisibleTypes) {
        *self.typedefs.borrow_mut() = Arc::clone(&types.typedef_types);
    }

    fn set_file_path(&self, path: &std::path::Path) {
        *self.file_path.borrow_mut() = path.to_string_lossy().into_owned();
    }
}

impl Msc37C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Calls that end a path the way a return does: `_Noreturn`
        // functions, and macros that return on the function's behalf. A
        // policy that does not trust the keyword keeps only the `_Noreturn`
        // functions whose bodies are verified never to return.
        let mut noreturn_names = Self::collect_noreturn_function_names(node, source);
        let bodies = self.visible_macro_bodies(source);
        noreturn_names.extend(self.keyword_noreturn_names(node, source, &bodies));
        let settings = self.settings.borrow();
        if !settings.flag("trust_noreturn_keyword") {
            let verified =
                crate::analyze::noreturn::collect_noreturn_function_names(node, source, &settings);
            noreturn_names.retain(|name| verified.contains(name));
        }
        if settings.flag("msc37_attribute_noreturn") {
            noreturn_names.extend(self.attribute_noreturn_names(node, source, &bodies));
        }
        // A macro that only sometimes returns ends the function's path, not
        // the arm that calls it: `break;` after `CHECK(x);` is reachable. A
        // name that also ends a path for another reason keeps doing so.
        let (returning, sometimes) = self.returning_macros(&bodies);
        *self.sometimes_returning.borrow_mut() = sometimes
            .into_iter()
            .filter(|name| !noreturn_names.contains(name))
            .collect();
        noreturn_names.extend(returning);
        // C23 `unreachable()` (C23 7.21.1) ends a path, where the edition is
        // declared and the file does not define a function or macro of that
        // name itself: CERT's EX2 helper named `unreachable` is that case.
        if self.c23_declared() && !defines_name(node, source, "unreachable") {
            noreturn_names.insert("unreachable".to_string());
        }
        // Check function definitions
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function_definition(&func, source, &noreturn_names, violations);
        }
    }
}

/// Whether a macro's replacement list returns on every path:
/// `return -1`, `do { log(); return -1; } while (0)`, or an `if`/`else` that
/// returns on both sides. `CHECK(x)` as `if (!(x)) return -1;` does not, and
/// neither does a body that can `break`, `continue` or `goto` past its
/// `return`. A body nested deeper than [`MACRO_BODY_DEPTH`] is read as not
/// always returning, so a pathological macro cannot overflow the stack.
fn macro_body_always_returns(body: &str) -> bool {
    /// Nesting beyond which a macro body is not followed.
    const MACRO_BODY_DEPTH: usize = 64;

    /// Whether a `break`, `continue` or `goto` under `node` leaves the
    /// enclosing block. A `break` aimed at a loop or `switch` nested inside
    /// `node` stays inside it, as does a `continue` aimed at a nested loop and
    /// a `goto` to a label the body itself defines.
    fn leaves_early(node: &Node, source: &str, depth: usize) -> bool {
        if depth > MACRO_BODY_DEPTH {
            return true;
        }
        let mut cursor = node.walk();
        let mut found = false;
        for child in node.named_children(&mut cursor) {
            found |= escapes(&child, source, false, false, depth + 1);
        }
        found
    }

    fn escapes(
        node: &Node,
        source: &str,
        break_caught: bool,
        continue_caught: bool,
        depth: usize,
    ) -> bool {
        if depth > MACRO_BODY_DEPTH {
            return true;
        }
        let (break_caught, continue_caught) = match node.kind() {
            "break_statement" => return !break_caught,
            "continue_statement" => return !continue_caught,
            "goto_statement" => return !goto_target_is_inside(node, source, depth),
            "while_statement" | "for_statement" | "do_statement" => (true, true),
            "switch_statement" => (true, continue_caught),
            _ => (break_caught, continue_caught),
        };
        let mut cursor = node.walk();
        let mut found = false;
        for child in node.named_children(&mut cursor) {
            found |= escapes(&child, source, break_caught, continue_caught, depth + 1);
        }
        found
    }

    /// Whether a `goto` stays inside the parsed body without skipping a
    /// return: its label precedes it (a backward jump), or the statement the
    /// label marks itself returns on every path.
    fn goto_target_is_inside(goto: &Node, source: &str, depth: usize) -> bool {
        let Some(label) = goto.child_by_field_name("label") else {
            return false;
        };
        let name = get_node_text(&label, source);
        let mut root = *goto;
        while let Some(p) = root.parent() {
            root = p;
        }
        query::find_descendants_of_kind(root, "labeled_statement")
            .into_iter()
            .filter(|l| {
                l.child_by_field_name("label")
                    .is_some_and(|n| get_node_text(&n, source) == name)
            })
            .any(|l| l.start_byte() < goto.start_byte() || always(&l, source, depth + 1))
    }

    fn leaves_early_stmt(node: &Node, source: &str, depth: usize) -> bool {
        escapes(node, source, false, false, depth + 1)
    }

    fn always(node: &Node, source: &str, depth: usize) -> bool {
        if depth > MACRO_BODY_DEPTH {
            return false;
        }
        match node.kind() {
            "return_statement" => true,
            "compound_statement" => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if always(&child, source, depth + 1) {
                        return true;
                    }
                    // A jump out of the block skips the return after it.
                    if leaves_early_stmt(&child, source, depth) {
                        return false;
                    }
                }
                false
            }
            // The body of a `do` runs at least once.
            "do_statement" => node
                .child_by_field_name("body")
                .is_some_and(|b| always(&b, source, depth + 1)),
            "if_statement" => match (
                node.child_by_field_name("consequence"),
                node.child_by_field_name("alternative"),
            ) {
                (Some(c), Some(a)) => {
                    always(&c, source, depth + 1) && always(&a, source, depth + 1)
                }
                _ => false,
            },
            // `done: return -1;`
            "labeled_statement" => node
                .named_child(node.named_child_count().saturating_sub(1))
                .is_some_and(|c| always(&c, source, depth + 1)),
            "else_clause" => node
                .named_child(0)
                .is_some_and(|c| always(&c, source, depth + 1)),
            // `switch (x) { default: return -1; }`: a `default` label, no
            // `break` aimed at the switch, and the last group returns.
            "switch_statement" => {
                let Some(body) = node.child_by_field_name("body") else {
                    return false;
                };
                let groups: Vec<Node> = {
                    let mut c = body.walk();
                    body.named_children(&mut c)
                        .filter(|k| k.kind() == "case_statement")
                        .collect()
                };
                let has_default = groups
                    .iter()
                    .any(|g| g.child_by_field_name("value").is_none());
                has_default
                    && !leaves_early(&body, source, depth)
                    && groups.last().is_some_and(|g| {
                        let mut c = g.walk();
                        let r = g
                            .named_children(&mut c)
                            .any(|k| always(&k, source, depth + 1));
                        r
                    })
            }
            _ => false,
        }
    }
    let text = format!("void f(void) {{ {body}\n; }}");
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&crate::parser::c_language()).is_err() {
        return false;
    }
    let Some(tree) = parser.parse(&text, None) else {
        return false;
    };
    query::find_first_descendant(tree.root_node(), |n| n.kind() == "function_definition")
        .and_then(|f| f.child_by_field_name("body"))
        .is_some_and(|b| always(&b, &text, 0))
}

/// The callee of `body` (a macro's replacement list) when the whole of it is
/// one call, `_fail(s, __FILE__)` or `halt()`; `None` for anything more or
/// less.
fn single_call_callee(body: &str) -> Option<&str> {
    let body = body.trim().trim_end_matches(';').trim_end();
    let open = body.find('(')?;
    let callee = body[..open].trim();
    if callee.is_empty()
        || !callee
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    let mut depth = 0usize;
    for (i, c) in body[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return (open + i + 1 == body.len()).then_some(callee);
                }
            }
            _ => {}
        }
    }
    None
}
