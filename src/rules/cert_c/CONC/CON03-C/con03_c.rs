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
use crate::analyze::check_macros::MacroDefinition;
use crate::analyze::concurrency_roots;
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{
    declaration_has_storage_class, get_node_text, resolve_identifier_binding_in, IdentifierBinding,
};
use crate::utility::cert_c::declarator_utils::{declares_function, inner_declarator};
use crate::utility::cert_c::overflow_helpers::resolve_typedef_chain;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

/// One object CON03-C may report, with the declaration it is reported at.
struct SharedVar<'a> {
    name: String,
    decl: Node<'a>,
    /// Declared at file scope. Every file-scope declaration of a name in one
    /// translation unit denotes the same object (C11 6.2.2), so a use that
    /// binds to no local and no parameter is a use of this one. A block-scope
    /// `static` is used only where a use resolves to a declaration of it.
    file_scope: bool,
    /// The block a block-scope `static` is declared in (`enclosing_block`);
    /// a use that resolves to any declaration of the name in that block is a
    /// use of it, whichever `#if` arm's declaration it found.
    block: Option<usize>,
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
    /// Every `#define` the prescan saw, so a lock type spelled through an
    /// object-like macro (`#define my_mutex_t pthread_mutex_t`) is still
    /// recognised as a lock.
    macro_definitions: RefCell<Arc<HashMap<String, Vec<MacroDefinition>>>>,
    /// The prescan's typedef aliases, for the same question asked of a
    /// typedef name.
    typedef_types: RefCell<Arc<HashMap<String, String>>>,
    /// Typedef names that name a function type (`typedef int (cb_t)(void);`):
    /// `static cb_t handler;` declares a function, not a variable.
    function_typedef_names: RefCell<Arc<HashSet<String>>>,
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
        *self.macro_definitions.borrow_mut() = Arc::clone(&context.macro_definitions);
        *self.typedef_types.borrow_mut() = Arc::clone(&context.typedef_types);
        *self.function_typedef_names.borrow_mut() = Arc::clone(&context.function_typedef_names);
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
    /// `static` is reached only through a declaration in its own block. An occurrence
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
                    Self::enclosing_block(&decl) == var.block
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
        // (scope, name) -> index in `shared_vars`: one object per name per
        // scope. The scope is `None` at file scope, else the block's id.
        let mut index: HashMap<(Option<usize>, String), usize> = HashMap::new();

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
            if self.is_synchronization_type(&decl_text) || self.declares_lock(&decl_node, source) {
                continue;
            }

            // Thread-local storage gives each thread its own object: nothing
            // is shared.
            if Self::is_thread_local(&decl_node, source) {
                continue;
            }

            // A `;` the parser had to invent means this is not a declaration
            // in the source: a macro attribute ahead of a function definition
            // (`BOOT_CODE` on its own line, then `static word_t f(...)`) reads
            // as `BOOT_CODE static word_t;`, whose "declarator" is a type name.
            if decl_node
                .child(decl_node.child_count().saturating_sub(1))
                .is_some_and(|last| last.is_missing())
            {
                continue;
            }

            let is_volatile = self.has_type_qualifier(&decl_node, source, "volatile");
            let is_atomic = self.has_atomic_type(&decl_node, source);
            let is_extern = self.has_storage_class(&decl_node, source, "extern");
            let block = Self::enclosing_block(&decl_node);
            let file_scope = block.is_none();

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
                // A prototype declares a function, not an object, and so does
                // a bare name declared through a function-type typedef.
                // A function cannot be initialized, so `= NULL` settles it.
                if declares_function(&declarator)
                    || (!initialized
                        && self.declares_function_through_typedef(&decl_node, &declarator, source))
                {
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
                    block,
                    initialized,
                    is_volatile,
                    is_atomic,
                };
                // Two declarations of one name in one scope are one object:
                // a tentative definition (`int x;`) and the definition, or the
                // alternatives of an `#if`/`#else` that each declare it. Report
                // it once, at the last definition, so a tentative definition
                // never displaces one with an initializer.
                match index.get(&(block, var.name.clone())) {
                    Some(&i) => {
                        if var.initialized || !shared_vars[i].initialized {
                            shared_vars[i] = var;
                        }
                    }
                    None => {
                        index.insert((block, var.name.clone()), shared_vars.len());
                        shared_vars.push(var);
                    }
                }
            }
        }
        shared_vars
    }

    /// The block a block-scope declaration belongs to, as its node id; `None`
    /// at file scope.
    fn enclosing_block(node: &Node) -> Option<usize> {
        let mut cur = node.parent();
        while let Some(p) = cur {
            match p.kind() {
                "compound_statement" => return Some(p.id()),
                "function_definition" => return Some(p.id()),
                _ => {}
            }
            cur = p.parent();
        }
        None
    }

    /// Whether `declarator` declares a function because the declaration's
    /// type is a typedef for a function type and the name is bare:
    /// `static handler_fn on_read;` declares a function, while
    /// `static handler_fn *on_read;` declares a pointer to one, an object.
    fn declares_function_through_typedef(
        &self,
        decl: &Node,
        declarator: &Node,
        source: &str,
    ) -> bool {
        let Some(ty) = decl.child_by_field_name("type") else {
            return false;
        };
        if ty.kind() != "type_identifier"
            || !self
                .function_typedef_names
                .borrow()
                .contains(get_node_text(&ty, source))
        {
            return false;
        }
        let mut d = *declarator;
        while d.kind() == "parenthesized_declarator" {
            match inner_declarator(&d) {
                Some(inner) => d = inner,
                None => return false,
            }
        }
        d.kind() == "identifier"
    }

    /// Whether the declaration gives its objects thread storage duration
    /// (`_Thread_local`, `thread_local`, `__thread`, `__declspec(thread)`).
    /// The grammar does not know `_Thread_local` in every position and may
    /// read it as a type name, so a type identifier spelled that way counts.
    fn is_thread_local(decl: &Node, source: &str) -> bool {
        let mut cursor = decl.walk();
        let found = decl.children(&mut cursor).any(|c| {
            let text = get_node_text(&c, source);
            match c.kind() {
                "storage_class_specifier" | "type_identifier" => {
                    matches!(text, "_Thread_local" | "thread_local" | "__thread")
                }
                "ms_declspec_modifier" => text.contains("thread"),
                _ => false,
            }
        });
        found
    }

    /// Whether the declaration's type names a lock through an object-like
    /// macro or a typedef the prescan saw: every definition of it, in every
    /// `#if` arm, resolves to a synchronization or atomic type. One arm that
    /// does not keeps the declaration, since which arm is compiled is unknown.
    fn declares_lock(&self, decl: &Node, source: &str) -> bool {
        let Some(ty) = decl.child_by_field_name("type") else {
            return false;
        };
        if ty.kind() != "type_identifier" {
            return false;
        }
        let macros = self.macro_definitions.borrow();
        let typedefs = self.typedef_types.borrow();
        let mut pending = vec![get_node_text(&ty, source).to_string()];
        let mut seen = HashSet::new();
        let mut resolved_any = false;
        while let Some(name) = pending.pop() {
            if !seen.insert(name.clone()) || seen.len() > 32 {
                continue;
            }
            if let Some(defs) = macros.get(&name) {
                for def in defs {
                    match def {
                        MacroDefinition::Object { body } => pending.push(body.trim().to_string()),
                        _ => return false,
                    }
                }
                resolved_any = true;
                continue;
            }
            let terminal = resolve_typedef_chain(&name, &typedefs);
            if terminal != name {
                resolved_any = true;
                pending.push(terminal);
                continue;
            }
            let is_lock = self.is_synchronization_type(&name)
                || name.contains("atomic_")
                || name.contains("_Atomic");
            if !is_lock {
                return false;
            }
        }
        resolved_any
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
            // Windows' locks, which a portability layer often reaches through
            // its own macro or typedef (`declares_lock` resolves those).
            "CRITICAL_SECTION",
            "SRWLOCK",
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
