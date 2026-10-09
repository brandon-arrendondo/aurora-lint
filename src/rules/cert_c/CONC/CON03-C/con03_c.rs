// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! CON03-C: Ensure visibility when accessing shared variables
//!
//! This rule detects shared primitive variables accessed across threads without proper
//! synchronization mechanisms. To ensure visibility of the most recent update, the write
//! to the variable must happen before the read.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! static int done = 0;  // Non-volatile, non-atomic shared flag
//!
//! void* worker_thread(void* arg) {
//!   while (!done) {
//!     // Do work...
//!   }
//!   return NULL;
//! }
//!
//! void shutdown() {
//!   done = 1;  // May not be visible to worker thread
//! }
//! ```
//!
//! **Compliant (volatile):**
//! ```c
//! static volatile int done = 0;  // Volatile ensures visibility
//!
//! void* worker_thread(void* arg) {
//!   while (!done) {
//!     // Do work...
//!   }
//!   return NULL;
//! }
//! ```
//!
//! **Compliant (mutex-protected):**
//! ```c
//! static int done = 0;
//! static mtx_t done_mutex;
//!
//! void* worker_thread(void* arg) {
//!   while (1) {
//!     mtx_lock(&done_mutex);
//!     int local_done = done;
//!     mtx_unlock(&done_mutex);
//!     if (local_done) break;
//!   }
//!   return NULL;
//! }
//!
//! void shutdown() {
//!   mtx_lock(&done_mutex);
//!   done = 1;
//!   mtx_unlock(&done_mutex);
//! }
//! ```
//!
//! **Compliant (atomic):**
//! ```c
//! #include <stdatomic.h>
//! static atomic_int done = ATOMIC_VAR_INIT(0);
//!
//! void* worker_thread(void* arg) {
//!   while (!atomic_load(&done)) {
//!     // Do work...
//!   }
//!   return NULL;
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Identify global/static variables that could be shared across threads
//! - Check if variables are declared volatile, atomic, or mutex-protected
//! - Flag variables that lack proper synchronization mechanisms

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg;
use crate::analyze::concurrency_roots;
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{
    declaration_has_storage_class, get_node_text, resolve_identifier_binding_in, IdentifierBinding,
};
use crate::utility::cert_c::declarator_utils::declares_function;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// One object CON03-C may report, with the declaration it is reported at.
struct SharedVar<'a> {
    name: String,
    decl: Node<'a>,
    /// Declared at file scope. Every file-scope declaration of a name in one
    /// translation unit denotes the same object (C11 6.2.2), so a use that
    /// binds to no local and no parameter is a use of this one. A block-scope
    /// `static` is used only where a use resolves to its own declaration.
    file_scope: bool,
    /// The reported declaration has an initializer, so it is the object's
    /// definition rather than a tentative one.
    initialized: bool,
    is_volatile: bool,
    is_atomic: bool,
}

#[derive(Debug, Default)]
pub struct Con03C {
    /// Function names reachable from a real concurrent-execution root (ISR,
    /// thread-spawn entry point, or `signal()` handler) — see an earlier fix /
    /// `docs/design/con03-con07-isr-thread-reachability.md`. Populated from
    /// `ProjectContext::concurrency_reachable` when a `-d` prescan ran;
    /// `check()` ORs it with a same-file-only fallback so the rule still
    /// works (reduced recall) on a single-file run.
    concurrency_reachable: RefCell<HashSet<String>>,
}

impl CertRule for Con03C {
    fn rule_id(&self) -> &'static str {
        "CON03-C"
    }

    fn description(&self) -> &'static str {
        "Ensure visibility when accessing shared variables"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "CON03-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        self.concurrency_reachable
            .borrow_mut()
            .extend(context.concurrency_reachable.iter().cloned());
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Same-file fallback, OR'd with whatever a `-d` prescan already
        // populated via set_project_context (see that method's docs).
        self.concurrency_reachable
            .borrow_mut()
            .extend(concurrency_roots::reachable_within_file(node, source));

        let shared_vars = self.collect_shared_variables(node, source);
        let uses = Self::identifier_uses_by_function(node, source);

        // Check each shared variable for proper synchronization
        for var in &shared_vars {
            if !var.is_volatile && !var.is_atomic {
                // CON03-C reports at the variable's *declaration* site, not
                // an access site, so reachability has to be checked at the
                // function(s) that actually touch the variable -- a
                // declaration is never itself a call-graph node. Skip
                // (rather than always flag) when no accessing function is
                // reachable from a concurrent root: the value can't race if
                // nothing that reads/writes it ever runs concurrently.
                // See docs/design/con03-con07-isr-thread-reachability.md.
                let reachable = self.concurrency_reachable.borrow();
                let is_reachable = uses.get(var.name.as_str()).is_some_and(|sites| {
                    sites.iter().any(|(func, id)| {
                        reachable.contains(func.as_str()) && Self::is_use_of(node, id, var, source)
                    })
                });
                drop(reachable);
                if !is_reachable {
                    continue;
                }

                let line = var.decl.start_position().row + 1;
                let column = var.decl.start_position().column + 1;
                let var_name = &var.name;
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "Shared variable '{}' lacks proper synchronization (not volatile or atomic). This may cause visibility issues across threads.",
                        var_name
                    ),
                    file_path: String::new(),
                    line,
                    column,
                    suggestion: Some(
                        "Consider declaring the variable as 'volatile', using atomic types (atomic_int, etc.), or protecting access with mutexes".to_string()
                    ),
                    ..Default::default()
                });
            }
        }

        violations
    }
}

impl Con03C {
    pub fn new() -> Self {
        Self::default()
    }

    /// The identifiers in each function body, grouped by spelling, with the
    /// name of the function they occur in. CON03-C reports at a variable's
    /// declaration, which is never a call-graph node, so reachability is
    /// judged at the functions that use the variable; [`Self::is_use_of`]
    /// decides which of these occurrences actually refer to it.
    fn identifier_uses_by_function<'a>(
        root: &Node<'a>,
        source: &'a str,
    ) -> HashMap<&'a str, Vec<(String, Node<'a>)>> {
        let mut uses: HashMap<&'a str, Vec<(String, Node<'a>)>> = HashMap::new();
        for func in query::find_descendants_of_kind(*root, "function_definition") {
            let Some(body) = func.child_by_field_name("body") else {
                continue;
            };
            let Some(name) = cfg::get_function_name(&func, source) else {
                continue;
            };
            for id in query::find_descendants_of_kind(body, "identifier") {
                uses.entry(get_node_text(&id, source))
                    .or_default()
                    .push((name.to_string(), id));
            }
        }
        uses
    }

    /// Whether `id`, an identifier spelled like `var`, refers to it. The
    /// occurrence is resolved by scope (ADR-0006): a local or a parameter of
    /// the same name shadows a file-scope variable, and a block-scope
    /// `static` is reached only through its own declaration. An occurrence
    /// that binds to nothing in this file (its file-scope declaration sits
    /// in an `#if` arm, say) still names the file-scope object: there is no
    /// inner declaration for it to name instead.
    fn is_use_of(root: &Node, id: &Node, var: &SharedVar, source: &str) -> bool {
        match resolve_identifier_binding_in(root, id, &var.name, source) {
            Some(IdentifierBinding::Local(decl)) => {
                if var.file_scope {
                    // `extern int x;` inside a block redeclares the file-scope `x`.
                    declaration_has_storage_class(&decl, "extern", source)
                } else {
                    decl.id() == var.decl.id()
                }
            }
            Some(IdentifierBinding::Parameter(_)) => false,
            Some(IdentifierBinding::Global(_)) | None => var.file_scope,
        }
    }

    /// Collect all global and static variables that could be shared across
    /// threads: every declarator of every such declaration, with or without
    /// an initializer, so `static int a, b;` yields both `a` and `b`.
    fn collect_shared_variables<'a>(&self, node: &Node<'a>, source: &str) -> Vec<SharedVar<'a>> {
        let mut shared_vars: Vec<SharedVar<'a>> = Vec::new();
        // File-scope name -> index in `shared_vars`: one object per name.
        let mut file_scope_index: HashMap<String, usize> = HashMap::new();

        for decl_node in query::find_descendants_of_kind(*node, "declaration") {
            // Check if this is a global or static declaration
            let is_static = self.has_storage_class(&decl_node, source, "static");
            let is_global = self.is_global_scope(&decl_node);

            if !(is_static || is_global) {
                continue;
            }

            // const-qualified variables are read-only — no data races possible
            if self.has_type_qualifier(&decl_node, source, "const") {
                continue;
            }

            // Synchronization primitives ARE the synchronization — don't flag them
            let decl_text = get_node_text(&decl_node, source);
            if self.is_synchronization_type(&decl_text) {
                continue;
            }

            let is_volatile = self.has_type_qualifier(&decl_node, source, "volatile");
            let is_atomic = self.has_atomic_type(&decl_node, source);
            let is_extern = self.has_storage_class(&decl_node, source, "extern");
            let file_scope = !Self::is_block_scope(&decl_node);

            let mut cursor = decl_node.walk();
            for child in decl_node.children_by_field_name("declarator", &mut cursor) {
                let (declarator, initialized) = if child.kind() == "init_declarator" {
                    match child.child_by_field_name("declarator") {
                        Some(d) => (d, true),
                        None => continue,
                    }
                } else {
                    (child, false)
                };
                // A prototype declares a function, not an object.
                if declares_function(&declarator) {
                    continue;
                }
                // `extern int x;` defines nothing: the object is reported at
                // its definition, in this file or another.
                if is_extern && !initialized {
                    continue;
                }
                let name = self.extract_variable_name(&declarator, source);
                if name.is_empty() {
                    continue;
                }
                let var = SharedVar {
                    name,
                    decl: decl_node,
                    file_scope,
                    initialized,
                    is_volatile,
                    is_atomic,
                };
                if !file_scope {
                    shared_vars.push(var);
                    continue;
                }
                // A tentative definition (`int x;`) and the definition
                // (`int x = 0;`) are one object; report it once, at the
                // definition when there is one.
                match file_scope_index.get(&var.name) {
                    Some(&i) => {
                        if var.initialized && !shared_vars[i].initialized {
                            shared_vars[i] = var;
                        }
                    }
                    None => {
                        file_scope_index.insert(var.name.clone(), shared_vars.len());
                        shared_vars.push(var);
                    }
                }
            }
        }
        shared_vars
    }

    /// Whether `node` lies inside a function (a block-scope declaration).
    fn is_block_scope(node: &Node) -> bool {
        let mut cur = node.parent();
        while let Some(p) = cur {
            if matches!(p.kind(), "compound_statement" | "function_definition") {
                return true;
            }
            cur = p.parent();
        }
        false
    }

    fn has_storage_class(&self, node: &Node, source: &str, class: &str) -> bool {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "storage_class_specifier" {
                    let text = get_node_text(&child, source);
                    if text == class {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_type_qualifier(&self, node: &Node, source: &str, qualifier: &str) -> bool {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "type_qualifier" {
                    let text = get_node_text(&child, source);
                    if text == qualifier {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_atomic_type(&self, node: &Node, source: &str) -> bool {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let text = get_node_text(&child, source);
                if text.contains("atomic_") || text.contains("_Atomic") {
                    return true;
                }
                // Check recursively in type specifiers
                if child.kind() == "type_specifier" && self.has_atomic_type(&child, source) {
                    return true;
                }
            }
        }
        false
    }

    fn is_synchronization_type(&self, decl_text: &str) -> bool {
        let sync_types = [
            "pthread_mutex_t",
            "pthread_rwlock_t",
            "pthread_cond_t",
            "pthread_spinlock_t",
            "pthread_barrier_t",
            "mtx_t",
            "cnd_t",
            "sem_t",
            // Zephyr RTOS declares its primitives as bare structs, never
            // through a typedef; matching `struct k_mutex` rather than
            // `k_mutex` keeps a field named `mask_sem` or a `k_mutex_lock`
            // call in the declaration text from counting.
            "struct k_mutex",
            "struct k_spinlock",
            "struct k_sem",
            "struct k_condvar",
        ];
        sync_types.iter().any(|t| decl_text.contains(t))
    }

    fn is_global_scope(&self, node: &Node) -> bool {
        // Check if parent is translation_unit (global scope)
        if let Some(parent) = node.parent() {
            parent.kind() == "translation_unit"
        } else {
            false
        }
    }

    fn extract_variable_name(&self, declarator: &Node, source: &str) -> String {
        // Handle different declarator types
        match declarator.kind() {
            "identifier" => get_node_text(declarator, source).to_string(),
            "pointer_declarator" | "array_declarator" => {
                // Navigate to the identifier
                if let Some(inner) = declarator.child_by_field_name("declarator") {
                    return self.extract_variable_name(&inner, source);
                }
                String::new()
            }
            _ => {
                // Try to find identifier in children
                for i in 0..declarator.child_count() {
                    if let Some(child) = declarator.child(i) {
                        if child.kind() == "identifier" {
                            return get_node_text(&child, source).to_string();
                        }
                        let name = self.extract_variable_name(&child, source);
                        if !name.is_empty() {
                            return name;
                        }
                    }
                }
                String::new()
            }
        }
    }
}
