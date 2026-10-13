// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! CON07-C: Ensure that compound operations on shared variables are atomic
//!
//! Compound operations are operations that consist of more than one discrete
//! operation. Expressions that include postfix or prefix increment (++), postfix or
//! prefix decrement (--), or compound assignment operators always result in compound
//! operations. Compound assignment expressions use operators such as *=, /=, %=,
//! +=, -=, <<=, >>=, ^=, and |=. Compound operations on shared variables must be
//! performed atomically to prevent data races.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! static int a;
//! static int b;
//!
//! int get_sum(void) {
//!   return a + b;  // Non-atomic compound operation on shared variables
//! }
//!
//! void set_values(int new_a, int new_b) {
//!   a = new_a;  // Non-atomic compound operation
//!   b = new_b;
//! }
//! ```
//!
//! **Compliant (Mutex):**
//! ```c
//! #include <threads.h>
//!
//! static int a;
//! static int b;
//! mtx_t flag_mutex;
//!
//! int get_sum(void) {
//!   if (thrd_success != mtx_lock(&flag_mutex)) {
//!     /* Handle error */
//!   }
//!   int sum = a + b;
//!   if (thrd_success != mtx_unlock(&flag_mutex)) {
//!     /* Handle error */
//!   }
//!   return sum;
//! }
//! ```
//!
//! **Compliant (Atomic struct):**
//! ```c
//! #include <stdatomic.h>
//!
//! static _Atomic struct ab_s {
//!   int a, b;
//! } ab;
//!
//! int get_sum(void) {
//!   struct ab_s new_ab = atomic_load(&ab);
//!   return new_ab.a + new_ab.b;
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find static variables that are accessed by multiple operations
//! - Detect compound operations: +=, -=, *=, /=, %=, <<=, >>=, ^=, |=, ++, --
//! - Check for functions that read multiple static variables without synchronization
//! - Look for functions that perform operations on static variables without mutex locks
//! - Check for absence of atomic operations or mutex locks
//! - A compound operation through a pointer (`(*p)++`, `p[i] += n`,
//!   `p->n++`) is judged by what the pointer points at, not by where the
//!   pointer itself is stored: a thread-local pointer into a shared array
//!   still mutates the array. It is reported, naming the shared object,
//!   only when every value the pointer is ever given (its initializer and
//!   each assignment, by declaration) is the address of, or into, a shared
//!   object. A pointer whose address is taken, a parameter, or one with any
//!   other origin points at something unknown, and is not reported.

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg;
use crate::analyze::concurrency_roots;
use crate::analyze::context::ProjectContext;
use crate::analyze::points_to::lvalue_of;
use crate::manifest::Severity;
use crate::settings::threads::ThreadOpKind;
use crate::utility::cert_c::ast_utils::{
    declaration_is_thread_local, get_identifier_from_declarator, get_node_text,
    resolve_identifier_binding, resolve_identifier_declarator, IdentifierBinding,
};
use crate::utility::cert_c::node_children::NodeChildren;
use crate::utility::cert_c::thread_api::{self, ProjectFunctions};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::HashSet;
use tree_sitter::Node;

/// The static/file-scope-global variables collected from a translation
/// unit, keyed by name to the byte offset(s) of the `declaration` node(s)
/// that bind them. Plain name matching against this set isn't enough
/// on its own -- a same-named local variable or parameter in an unrelated
/// scope would be misattributed as an access to the shared variable.
/// [`StaticVars::resolves`] closes that gap by checking, via
/// [`resolve_identifier_binding`], that a candidate identifier occurrence
/// actually binds to one of the recorded declarations rather than shadowing
/// it.
#[derive(Debug, Default)]
struct StaticVars {
    decls: HashMap<String, Vec<usize>>,
}

impl StaticVars {
    fn record(&mut self, name: String, decl_start: usize) {
        self.decls.entry(name).or_default().push(decl_start);
    }

    fn contains(&self, name: &str) -> bool {
        self.decls.contains_key(name)
    }

    /// True if `id_node` (an occurrence of `name`) actually resolves to one
    /// of the recorded declarations for that name, rather than a same-named
    /// local variable or parameter shadowing it in this scope.
    fn resolves(&self, id_node: &Node, name: &str, source: &str) -> bool {
        let Some(starts) = self.decls.get(name) else {
            return false;
        };
        match resolve_identifier_binding(id_node, name, source) {
            Some(IdentifierBinding::Local(decl)) | Some(IdentifierBinding::Global(decl)) => {
                starts.contains(&decl.start_byte())
            }
            _ => false,
        }
    }
}

#[derive(Debug, Default)]
pub struct Con07C {
    /// Function names reachable from a real concurrent-execution root (ISR,
    /// thread-spawn entry point, or `signal()` handler) — see an earlier fix /
    /// `docs/design/con03-con07-isr-thread-reachability.md`. Populated from
    /// `ProjectContext::concurrency_reachable` when a `-d` prescan ran;
    /// `check()` ORs it with a same-file-only fallback so the rule still
    /// works (reduced recall) on a single-file run.
    concurrency_reachable: RefCell<HashSet<String>>,
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
    /// Per translation unit: what each pointer is proven to point into,
    /// worked out once per pointer however many writes go through it.
    pointers: RefCell<PointerFacts>,
}

/// What [`proven_pointees`] needs about one translation unit beyond the
/// pointer itself, built once per file.
#[derive(Debug, Default)]
struct PointerFacts {
    /// Every identifier token in a `#define` body: a pointer named in one
    /// may be retargeted where the tree does not show it.
    macro_tokens: HashSet<String>,
    /// [`proven_pointees`] by the pointer's declaration start byte.
    pointees: HashMap<usize, Option<Vec<String>>>,
}

/// What [`compound_writes_through_pointers`] found in a function body.
#[derive(Debug, Default)]
struct ThroughPointers {
    /// The shared objects written through a pointer.
    pointees: Vec<String>,
    /// The pointers those writes went through.
    pointers: Vec<String>,
}

impl CertRule for Con07C {
    fn rule_id(&self) -> &'static str {
        "CON07-C"
    }

    fn description(&self) -> &'static str {
        "Ensure that compound operations on shared variables are atomic"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "CON07-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        self.concurrency_reachable
            .borrow_mut()
            .extend(context.concurrency_reachable.iter().cloned());
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First pass: collect static variables
        let static_vars = self.collect_static_variables(node, source);
        *self.pointers.borrow_mut() = PointerFacts {
            macro_tokens: macro_body_tokens(node, source),
            pointees: HashMap::new(),
        };

        // Same-file fallback, OR'd with whatever a `-d` prescan already
        // populated via set_project_context (see that method's docs).
        self.concurrency_reachable
            .borrow_mut()
            .extend(concurrency_roots::reachable_within_file(node, source));

        // Second pass: check for non-atomic compound operations on these variables
        self.check_node(node, source, &static_vars, &mut violations);

        violations
    }
}

impl Con07C {
    pub fn new() -> Self {
        Self::default()
    }

    /// Collect all static variable names from the translation unit
    fn collect_static_variables(&self, node: &Node, source: &str) -> StaticVars {
        let mut static_vars = StaticVars::default();
        self.find_static_variables(node, source, &mut static_vars);
        static_vars
    }

    fn find_static_variables(&self, node: &Node, source: &str, static_vars: &mut StaticVars) {
        for decl_node in query::find_descendants_of_kind(*node, "declaration") {
            let mut var_names = Vec::new();

            for i in 0..decl_node.child_count() {
                if let Some(child) = decl_node.child(i) {
                    match child.kind() {
                        "init_declarator" => {
                            // Case: static int a = 0;
                            if let Some(declarator) = child.child_by_field_name("declarator") {
                                let name = get_identifier_from_declarator(&declarator, source);
                                if !name.is_empty() {
                                    var_names.push(name);
                                }
                            }
                        }
                        "identifier" => {
                            // Case: static int a;  (no initializer)
                            var_names.push(get_node_text(&child, source).to_string());
                        }
                        _ => {}
                    }
                }
            }

            if declaration_is_shared(&decl_node, source) {
                for name in var_names {
                    static_vars.record(name, decl_node.start_byte());
                }
            }
        }
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        static_vars: &StaticVars,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for function definitions that might access static variables
        for func_node in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function_for_non_atomic_operations(
                &func_node,
                source,
                static_vars,
                violations,
            );
        }
    }

    fn check_function_for_non_atomic_operations(
        &self,
        function_node: &Node,
        source: &str,
        static_vars: &StaticVars,
        violations: &mut Vec<RuleViolation>,
    ) {
        let func_name = cfg::get_function_name(function_node, source)
            .unwrap_or("<unknown>")
            .to_string();

        // Skip initialization functions (they run before threading typically)
        if func_name.to_lowercase().contains("init") {
            return;
        }

        // Skip functions that use mutex locks (compliant)
        if self.uses_mutex_lock(function_node, source) {
            return;
        }

        // Skip functions never reachable from a real concurrent-execution
        // root (ISR, thread-spawn entry point, signal() handler) -- a
        // compound operation that only ever runs on one execution path
        // can't race with itself. See an earlier fix /
        // docs/design/con03-con07-isr-thread-reachability.md.
        if !self
            .concurrency_reachable
            .borrow()
            .contains(func_name.as_str())
        {
            return;
        }

        // Get function body
        let body = match function_node.child_by_field_name("body") {
            Some(b) => b,
            None => return,
        };

        // Check for compound operations on static variables, and on the
        // shared objects a pointer is proven to point into
        let mut static_var_accesses = self.find_static_var_accesses(&body, source, static_vars);
        let through =
            compound_writes_through_pointers(&body, source, &mut self.pointers.borrow_mut());
        // A shared pointer that is only read through is not itself an
        // object the operation is on
        static_var_accesses.retain(|name| {
            !through.pointers.contains(name)
                || !only_dereferenced_in(&body, name, source, static_vars)
        });
        let through_pointers = through.pointees;
        static_var_accesses.extend(through_pointers.iter().cloned());
        static_var_accesses.sort();
        static_var_accesses.dedup();

        // A single atomic operation spanning ALL the shared state involved
        // (e.g. one atomic_load/atomic_store on an _Atomic struct, or a
        // single atomic RMW on one variable) is compliant — that's exactly
        // why it collapses to a single tracked variable name here. But
        // wrapping each variable's access in its own SEPARATE atomic_*
        // call does NOT make combining them atomic (CERT's own "Addition
        // of Atomic Integers" noncompliant example) — so, unlike a lone
        // atomic variable, this blanket exemption must not apply once
        // multiple distinct shared variables are involved.
        if static_var_accesses.len() == 1 && self.uses_atomic_operations(function_node, source) {
            return;
        }

        // If function performs a compound write on multiple static variables, flag it.
        // Pure reads of multiple statics are not a compound-operation violation.
        if static_var_accesses.len() > 1 {
            let has_compound_write = !through_pointers.is_empty()
                || static_var_accesses
                    .iter()
                    .any(|v| self.has_compound_operation_on_var(&body, source, v, static_vars));
            let combines_reads = self.combines_multiple_vars(&body, source, static_vars);
            let writes_multiple = self.writes_multiple_vars(&body, source, static_vars);
            if has_compound_write || combines_reads || writes_multiple {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "Function '{}' performs compound operation on shared static variables ({}) without synchronization",
                        func_name,
                        static_var_accesses.join(", ")
                    ),
                    file_path: String::new(),
                    line: function_node.start_position().row + 1,
                    column: function_node.start_position().column + 1,
                    suggestion: Some(
                        "Use mutex locks (mtx_lock/mtx_unlock) or atomic operations to ensure atomicity".to_string()
                    ),
                    ..Default::default()
                });
            }
        } else if static_var_accesses.len() == 1 {
            // Check for compound assignment operations on a single static variable
            if !through_pointers.is_empty()
                || self.has_compound_operation_on_var(
                    &body,
                    source,
                    &static_var_accesses[0],
                    static_vars,
                )
            {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "Function '{}' performs compound operation on shared static variable '{}' without synchronization",
                        func_name,
                        static_var_accesses[0]
                    ),
                    file_path: String::new(),
                    line: function_node.start_position().row + 1,
                    column: function_node.start_position().column + 1,
                    suggestion: Some(
                        "Use mutex locks (mtx_lock/mtx_unlock) or atomic operations to ensure atomicity".to_string()
                    ),
                    ..Default::default()
                });
            }
        }
    }

    fn uses_mutex_lock(&self, node: &Node, source: &str) -> bool {
        let project = self.project.borrow();
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            // A lock or unlock by its thread-API contract: C11, POSIX and
            // any declared family.
            if thread_api::thread_op(&n, source, project.as_ref()).is_some_and(|call| {
                matches!(
                    call.kind(),
                    ThreadOpKind::MutexLock | ThreadOpKind::MutexUnlock
                )
            }) {
                return true;
            }
            let Some(func) = n.child_by_field_name("function") else {
                return false;
            };
            let func_name = get_node_text(&func, source);
            // Locks no thread-API family describes yet.
            matches!(
                func_name,
                "stdThreadLockAcquire"
                    | "stdThreadLockRelease"
                    // Zephyr RTOS: mutex, spinlock (the type is `struct
                    // k_spinlock`, the calls are `k_spin_*`), and the
                    // interrupt-masking critical section older Zephyr code
                    // uses in place of either.
                    | "k_mutex_lock"
                    | "k_mutex_unlock"
                    | "k_spin_lock"
                    | "k_spin_unlock"
                    | "irq_lock"
                    | "irq_unlock"
            )
        })
        .is_some()
    }

    fn uses_atomic_operations(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() == "call_expression" {
                if let Some(func) = n.child_by_field_name("function") {
                    let func_name = get_node_text(&func, source);
                    if func_name.starts_with("atomic_") {
                        return true;
                    }
                }
            }

            // Check for _Atomic type qualifier
            if n.kind() == "type_qualifier" {
                let text = get_node_text(&n, source);
                if text == "_Atomic" {
                    return true;
                }
            }

            false
        })
        .is_some()
    }

    fn find_static_var_accesses(
        &self,
        node: &Node,
        source: &str,
        static_vars: &StaticVars,
    ) -> Vec<String> {
        let mut accesses = Vec::new();
        self.collect_static_var_accesses(node, source, static_vars, &mut accesses);
        accesses.sort();
        accesses.dedup();
        accesses
    }

    fn collect_static_var_accesses(
        &self,
        node: &Node,
        source: &str,
        static_vars: &StaticVars,
        accesses: &mut Vec<String>,
    ) {
        for id_node in query::find_descendants_of_kind(*node, "identifier") {
            let name = get_node_text(&id_node, source);
            if static_vars.contains(name) && static_vars.resolves(&id_node, name, source) {
                accesses.push(name.to_string());
            }
        }
    }

    fn has_compound_operation_on_var(
        &self,
        node: &Node,
        source: &str,
        var_name: &str,
        static_vars: &StaticVars,
    ) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() == "assignment_expression" {
                let left = n.child_by_field_name("left");
                let right = n.child_by_field_name("right");
                if let Some(left_node) = left {
                    let left_text = get_node_text(&left_node, source);
                    if left_text == var_name
                        && left_node.kind() == "identifier"
                        && static_vars.resolves(&left_node, var_name, source)
                    {
                        // Compound assignment: x += 1, x -= 1, etc.
                        if let Some(operator) = n.child_by_field_name("operator") {
                            let op_text = get_node_text(&operator, source);
                            if matches!(
                                op_text,
                                "+=" | "-="
                                    | "*="
                                    | "/="
                                    | "%="
                                    | "<<="
                                    | ">>="
                                    | "&="
                                    | "^="
                                    | "|="
                            ) {
                                return true;
                            }
                        }
                        // Read-modify-write: x = x OP expr (var appears in RHS)
                        if let Some(right_node) = right {
                            if query::find_descendants_of_kind(right_node, "identifier")
                                .into_iter()
                                .any(|id| {
                                    get_node_text(&id, source) == var_name
                                        && static_vars.resolves(&id, var_name, source)
                                })
                            {
                                return true;
                            }
                        }
                    }
                }
            }

            // Increment/decrement: x++, ++x, x--, --x
            if matches!(n.kind(), "update_expression") {
                if let Some(argument) = n.child_by_field_name("argument") {
                    if get_node_text(&argument, source) == var_name
                        && argument.kind() == "identifier"
                        && static_vars.resolves(&argument, var_name, source)
                    {
                        return true;
                    }
                }
            }

            false
        })
        .is_some()
    }

    /// Names from `static_vars` referenced anywhere in `node`'s subtree,
    /// excluding occurrences that actually resolve to a same-named
    /// shadowing local variable or parameter rather than the shared one.
    fn vars_referenced_in(
        &self,
        node: &Node,
        source: &str,
        static_vars: &StaticVars,
    ) -> std::collections::HashSet<String> {
        let mut found = std::collections::HashSet::new();
        for id_node in query::find_descendants_of_kind(*node, "identifier") {
            let name = get_node_text(&id_node, source);
            if static_vars.contains(name) && static_vars.resolves(&id_node, name, source) {
                found.insert(name.to_string());
            }
        }
        found
    }

    /// True if any single expression (e.g. `a + b`, or
    /// `atomic_load(&a) + atomic_load(&b)`) combines reads of two or more
    /// distinct shared variables — each read may individually be atomic,
    /// but the combination isn't (CERT's "Addition of Atomic Integers"
    /// noncompliant example).
    fn combines_multiple_vars(&self, body: &Node, source: &str, static_vars: &StaticVars) -> bool {
        query::find_descendants_of_kind(*body, "binary_expression")
            .into_iter()
            .any(|expr| self.vars_referenced_in(&expr, source, static_vars).len() > 1)
    }

    /// True if two or more distinct shared variables are each individually
    /// written (plain assignment or an atomic store/exchange/init call)
    /// somewhere in this function — writing correlated shared state one
    /// variable at a time is not atomic as a whole, even if each
    /// individual write is.
    fn writes_multiple_vars(&self, body: &Node, source: &str, static_vars: &StaticVars) -> bool {
        let mut written = std::collections::HashSet::new();

        for assign in query::find_descendants_of_kind(*body, "assignment_expression") {
            if let Some(left) = assign.child_by_field_name("left") {
                let left_text = get_node_text(&left, source);
                if left.kind() == "identifier"
                    && static_vars.contains(left_text)
                    && static_vars.resolves(&left, left_text, source)
                {
                    written.insert(left_text.to_string());
                }
            }
        }

        for call in query::find_descendants_of_kind(*body, "call_expression") {
            let Some(func) = call.child_by_field_name("function") else {
                continue;
            };
            let func_name = get_node_text(&func, source);
            if !matches!(
                func_name,
                "atomic_store"
                    | "atomic_store_explicit"
                    | "atomic_exchange"
                    | "atomic_exchange_explicit"
                    | "atomic_init"
            ) {
                continue;
            }
            let Some(args) = call.child_by_field_name("arguments") else {
                continue;
            };
            if let Some(first_arg) = args.named_child(0) {
                written.extend(self.vars_referenced_in(&first_arg, source, static_vars));
            }
        }

        written.len() > 1
    }
}

/// Whether the objects `decl` (a `declaration`) declares are shared between
/// threads: `static` ones, and file-scope ones this file owns (not
/// `extern`) that are not a mutex or thread handle. An object with thread
/// storage duration is each thread's own, so no other thread shares it.
fn declaration_is_shared(decl: &Node, source: &str) -> bool {
    if declaration_is_thread_local(decl, source) {
        return false;
    }
    let mut is_static = false;
    let mut is_file_scope = decl
        .parent()
        .is_some_and(|p| p.kind() == "translation_unit");
    let mut is_mutex_or_thread_type = false;
    for child in decl.child_nodes() {
        match child.kind() {
            "storage_class_specifier" => match get_node_text(&child, source) {
                "static" => is_static = true,
                // extern declarations are not owned by this file
                "extern" => is_file_scope = false,
                _ => {}
            },
            "type_identifier" => {
                let type_name = get_node_text(&child, source);
                if type_name.contains("mutex")
                    || type_name.contains("pthread")
                    || type_name.contains("thrd")
                    || type_name.contains("cnd")
                {
                    is_mutex_or_thread_type = true;
                }
            }
            _ => {}
        }
    }
    is_static || (is_file_scope && !is_mutex_or_thread_type)
}

/// The shared objects `body` performs a compound operation on through a
/// pointer: a compound assignment, an increment or decrement, or
/// `*p = *p + n`, whose target is `*p`, `p[i]`, `p->f` or `*(p + k)`, where
/// `p` is proven to point into shared objects ([`proven_pointees`]), and
/// the pointers they went through.
fn compound_writes_through_pointers(
    body: &Node,
    source: &str,
    facts: &mut PointerFacts,
) -> ThroughPointers {
    let mut found = ThroughPointers::default();
    for op in
        query::find_descendants_of_kinds(*body, &["assignment_expression", "update_expression"])
    {
        let target = if op.kind() == "update_expression" {
            op.child_by_field_name("argument")
        } else {
            op.child_by_field_name("left")
                .filter(|left| is_compound_assignment(&op, left, source))
        };
        let Some(pointer) = target.and_then(|t| pointer_through(&t, source)) else {
            continue;
        };
        let name = get_node_text(&pointer, source);
        let Some((decl, declarator)) = resolve_identifier_declarator(&pointer, name, source) else {
            continue;
        };
        let pointees = facts.pointees.entry(decl.start_byte()).or_insert_with(|| {
            proven_pointees(&decl, &declarator, name, source, &facts.macro_tokens)
        });
        if let Some(objects) = pointees {
            found.pointees.extend(objects.iter().cloned());
            found.pointers.push(name.to_string());
        }
    }
    for list in [&mut found.pointees, &mut found.pointers] {
        list.sort();
        list.dedup();
    }
    found
}

/// Whether every occurrence of the shared variable `name` in `body` is a
/// pointer being dereferenced (`*name`, `name[i]`, `name->f`), never the
/// pointer itself being read or written.
fn only_dereferenced_in(body: &Node, name: &str, source: &str, static_vars: &StaticVars) -> bool {
    query::find_descendants_of_kind(*body, "identifier")
        .into_iter()
        .filter(|id| get_node_text(id, source) == name && static_vars.resolves(id, name, source))
        .all(|id| {
            let mut child = id;
            while let Some(parent) = child.parent() {
                match parent.kind() {
                    "parenthesized_expression" | "cast_expression" => child = parent,
                    "binary_expression" if parent.child_by_field_name("left") == Some(child) => {
                        child = parent
                    }
                    _ => return pointer_through(&parent, source) == Some(id),
                }
            }
            false
        })
}

/// Every identifier token in the body of a `#define` in `root`, apart from
/// a function-like macro's own parameters.
fn macro_body_tokens(root: &Node, source: &str) -> HashSet<String> {
    let tokens = |text: &str| -> Vec<String> {
        text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|token| !token.is_empty())
            .map(str::to_string)
            .collect()
    };
    let mut found = HashSet::new();
    for def in query::find_descendants_of_kinds(*root, &["preproc_def", "preproc_function_def"]) {
        let Some(value) = def.child_by_field_name("value") else {
            continue;
        };
        let params = def
            .child_by_field_name("parameters")
            .map(|p| tokens(get_node_text(&p, source)))
            .unwrap_or_default();
        found.extend(
            tokens(get_node_text(&value, source))
                .into_iter()
                .filter(|token| !params.contains(token)),
        );
    }
    found
}

/// Whether the assignment `op` to `left` reads what it writes: a compound
/// operator, or `=` with the same location on the right (`*p = *p + 1`).
fn is_compound_assignment(op: &Node, left: &Node, source: &str) -> bool {
    let operator = op
        .child_by_field_name("operator")
        .map(|o| get_node_text(&o, source))
        .unwrap_or("=");
    if operator != "=" {
        return true;
    }
    let (Some(target), Some(right)) = (lvalue_of(left, source), op.child_by_field_name("right"))
    else {
        return false;
    };
    query::find_first_descendant(right, |n| {
        matches!(
            n.kind(),
            "pointer_expression" | "subscript_expression" | "field_expression"
        ) && lvalue_of(&n, source).as_ref() == Some(&target)
    })
    .is_some()
}

/// The pointer variable an lvalue writes through: `p` in `*p`, `p[i]`,
/// `p->f` and `*(p + k)`, through parentheses and casts. `None` for a
/// plain variable, a `.` member, or a pointer that is not a bare name.
fn pointer_through<'a>(target: &Node<'a>, source: &str) -> Option<Node<'a>> {
    let target = strip_parens_and_casts(*target);
    let base = match target.kind() {
        "pointer_expression"
            if target
                .child_by_field_name("operator")
                .is_some_and(|o| get_node_text(&o, source) == "*") =>
        {
            target.child_by_field_name("argument")?
        }
        "subscript_expression" => target.child_by_field_name("argument")?,
        "field_expression"
            if target
                .child_by_field_name("operator")
                .is_some_and(|o| get_node_text(&o, source) == "->") =>
        {
            target.child_by_field_name("argument")?
        }
        _ => return None,
    };
    let mut base = strip_parens_and_casts(base);
    if base.kind() == "binary_expression" {
        base = strip_parens_and_casts(base.child_by_field_name("left")?);
    }
    (base.kind() == "identifier").then_some(base)
}

/// The shared objects the pointer `name`, declared by `declarator` in
/// `decl`, is proven to point into: every value it is ever given -- its
/// initializer and each plain assignment, pointer arithmetic keeping the
/// object -- is the address of, or into, a shared object. Occurrences are
/// matched by declaration (ADR-0006), within the declaring block for a
/// block-scope pointer. `None` when the pointer is a parameter, has external
/// linkage (another file may retarget it), is named in a macro body, has
/// its address taken, has no origin, or any origin is something else (a
/// thread-local object, another pointer, a call).
fn proven_pointees(
    decl: &Node,
    declarator: &Node,
    name: &str,
    source: &str,
    macro_tokens: &HashSet<String>,
) -> Option<Vec<String>> {
    if decl.kind() != "declaration"
        || pointer_derivations(declarator).first() != Some(&"pointer_declarator")
        || macro_tokens.contains(name)
    {
        return None;
    }
    let scope = decl.parent()?;
    let storage: Vec<&str> = decl
        .child_nodes()
        .filter(|c| c.kind() == "storage_class_specifier")
        .map(|c| get_node_text(&c, source))
        .collect();
    let file_scope = scope.kind() == "translation_unit";
    if storage.contains(&"extern") || (file_scope && !storage.contains(&"static")) {
        return None;
    }
    let declared = declarator_name(declarator)?;
    let mut origins: Vec<Node> = declarator
        .parent()
        .filter(|p| p.kind() == "init_declarator")
        .and_then(|p| p.child_by_field_name("value"))
        .into_iter()
        .collect();
    for occurrence in query::find_descendants_of_kind(scope, "identifier") {
        if occurrence == declared
            || get_node_text(&occurrence, source) != name
            || resolve_identifier_declarator(&occurrence, name, source)
                .is_none_or(|(d, _)| d != *decl)
        {
            continue;
        }
        // `(p) = ...` and `&(p)` name the pointer as surely as `p` does
        let mut child = occurrence;
        let mut parent = occurrence.parent();
        while let Some(p) = parent.filter(|p| p.kind() == "parenthesized_expression") {
            child = p;
            parent = p.parent();
        }
        let Some(parent) = parent else {
            continue;
        };
        match parent.kind() {
            "assignment_expression" if parent.child_by_field_name("left") == Some(child) => {
                match parent
                    .child_by_field_name("operator")
                    .map(|o| get_node_text(&o, source))
                {
                    Some("=") => origins.push(parent.child_by_field_name("right")?),
                    Some("+=" | "-=") => {}
                    _ => return None,
                }
            }
            "pointer_expression"
                if parent
                    .child_by_field_name("operator")
                    .is_some_and(|o| get_node_text(&o, source) == "&") =>
            {
                return None;
            }
            _ => {}
        }
    }
    if origins.is_empty() {
        return None;
    }
    let mut objects = Vec::new();
    for origin in origins {
        objects.push(shared_object_addressed(&origin, source)?);
    }
    objects.sort();
    objects.dedup();
    Some(objects)
}

/// The kinds of declarator `declarator` derives its identifier's type by,
/// the one applied to the identifier first: `[pointer_declarator,
/// array_declarator]` for `(*p)[4]`, a pointer to an array, and the reverse
/// for `*p[4]`, an array of pointers.
fn pointer_derivations(declarator: &Node) -> Vec<&'static str> {
    let mut kinds = Vec::new();
    let mut node = *declarator;
    while node.kind() != "identifier" {
        let inner = if node.kind() == "parenthesized_declarator" {
            node.named_child(0)
        } else {
            kinds.push(node.kind());
            node.child_by_field_name("declarator")
        };
        let Some(inner) = inner else {
            break;
        };
        node = inner;
    }
    kinds.reverse();
    kinds
}

/// The identifier a declarator declares.
fn declarator_name<'a>(declarator: &Node<'a>) -> Option<Node<'a>> {
    let mut node = *declarator;
    loop {
        if node.kind() == "identifier" {
            return Some(node);
        }
        node = if node.kind() == "parenthesized_declarator" {
            node.named_child(0)?
        } else {
            node.child_by_field_name("declarator")?
        };
    }
}

/// The shared object `value` is the address of or into: `&x`, `&x[i]`,
/// `&x.f`, an array `x` (which decays to its first element's address), or
/// any of these plus or minus an offset, `x` resolving by declaration to a
/// shared object ([`declaration_is_shared`]). Each subscript, and a
/// decaying `x`, must be of an array `x` is declared as: subscripting a
/// pointer reaches its pointee, not `x`, and a member's type is not known,
/// so `&x.f[i]` is not proven.
fn shared_object_addressed(value: &Node, source: &str) -> Option<String> {
    let value = strip_parens_and_casts(*value);
    // Each step from `x` to the addressed object, outermost first
    let mut steps = Vec::new();
    let object = match value.kind() {
        "binary_expression" => {
            return shared_object_addressed(&value.child_by_field_name("left")?, source)
        }
        "pointer_expression"
            if value
                .child_by_field_name("operator")
                .is_some_and(|o| get_node_text(&o, source) == "&") =>
        {
            let mut object = strip_parens_and_casts(value.child_by_field_name("argument")?);
            while matches!(object.kind(), "subscript_expression" | "field_expression") {
                if object.kind() == "field_expression"
                    && object
                        .child_by_field_name("operator")
                        .is_some_and(|o| get_node_text(&o, source) == "->")
                {
                    return None;
                }
                steps.push(object.kind());
                object = strip_parens_and_casts(object.child_by_field_name("argument")?);
            }
            object
        }
        "identifier" => {
            steps.push("subscript_expression");
            value
        }
        _ => return None,
    };
    if object.kind() != "identifier" {
        return None;
    }
    let name = get_node_text(&object, source);
    let (decl, declarator) = resolve_identifier_declarator(&object, name, source)?;
    if decl.kind() != "declaration" || !declaration_is_shared(&decl, source) {
        return None;
    }
    let mut derivations = pointer_derivations(&declarator).into_iter();
    let mut in_member = false;
    for step in steps.into_iter().rev() {
        if step == "field_expression" {
            in_member = true;
        } else if in_member || derivations.next() != Some("array_declarator") {
            return None;
        }
    }
    Some(name.to_string())
}

/// `node` with any enclosing parentheses and casts removed.
fn strip_parens_and_casts(mut node: Node) -> Node {
    loop {
        match node.kind() {
            "parenthesized_expression" => match node.named_child(0) {
                Some(inner) => node = inner,
                None => return node,
            },
            "cast_expression" => match node.child_by_field_name("value") {
                Some(inner) => node = inner,
                None => return node,
            },
            _ => return node,
        }
    }
}
