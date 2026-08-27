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
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

#[derive(Debug, Default)]
pub struct Con03C {
    /// Function names reachable from a real concurrent-execution root (ISR,
    /// thread-spawn entry point, or `signal()` handler) — see task 608 /
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

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
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

        // Collect all potentially shared variables (global/static)
        // HashMap: var_name -> (line, column, is_volatile, is_atomic)
        let mut shared_vars: HashMap<String, (usize, usize, bool, bool)> = HashMap::new();
        self.collect_shared_variables(node, source, &mut shared_vars);

        // Check each shared variable for proper synchronization
        for (var_name, (line, column, is_volatile, is_atomic)) in shared_vars {
            if !is_volatile && !is_atomic {
                // CON03-C reports at the variable's *declaration* site, not
                // an access site, so reachability has to be checked at the
                // function(s) that actually touch the variable -- a
                // declaration is never itself a call-graph node. Skip
                // (rather than always flag) when no accessing function is
                // reachable from a concurrent root: the value can't race if
                // nothing that reads/writes it ever runs concurrently.
                // Task 608 / docs/design/con03-con07-isr-thread-reachability.md.
                let accessors = self.collect_accessing_functions(node, &var_name, source);
                let reachable = self.concurrency_reachable.borrow();
                let is_reachable = accessors.iter().any(|f| reachable.contains(f.as_str()));
                drop(reachable);
                if !is_reachable {
                    continue;
                }

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

    /// Every function whose body contains at least one reference to
    /// `var_name` (identifier text match — same precision level as the
    /// rest of this rule, no scope/shadowing analysis). CON03-C reports at
    /// the variable's declaration site, which is itself never a call-graph
    /// node, so this is how reachability gets checked instead (task 608).
    fn collect_accessing_functions(
        &self,
        root: &Node,
        var_name: &str,
        source: &str,
    ) -> HashSet<String> {
        let mut out = HashSet::new();
        for func in query::find_descendants_of_kind(*root, "function_definition") {
            let Some(body) = func.child_by_field_name("body") else {
                continue;
            };
            let touches = query::find_descendants_of_kind(body, "identifier")
                .into_iter()
                .any(|id| get_node_text(&id, source) == var_name);
            if touches {
                if let Some(name) = cfg::get_function_name(&func, source) {
                    out.insert(name.to_string());
                }
            }
        }
        out
    }

    /// Collect all global and static variables that could be shared across threads
    fn collect_shared_variables(
        &self,
        node: &Node,
        source: &str,
        shared_vars: &mut HashMap<String, (usize, usize, bool, bool)>,
    ) {
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

            let line = decl_node.start_position().row + 1;
            let column = decl_node.start_position().column + 1;

            // Extract variable names from this declaration
            if let Some(declarator_list) = self.find_child_by_kind(&decl_node, "init_declarator") {
                if let Some(declarator) = declarator_list.child_by_field_name("declarator") {
                    let var_name = self.extract_variable_name(&declarator, source);
                    if !var_name.is_empty() {
                        shared_vars.insert(var_name, (line, column, is_volatile, is_atomic));
                    }
                }
            } else {
                // Try direct declarator
                for i in 0..decl_node.child_count() {
                    if let Some(child) = decl_node.child(i) {
                        if child.kind() == "init_declarator" {
                            if let Some(declarator) = child.child_by_field_name("declarator") {
                                let var_name = self.extract_variable_name(&declarator, source);
                                if !var_name.is_empty() {
                                    shared_vars
                                        .insert(var_name, (line, column, is_volatile, is_atomic));
                                }
                            }
                        }
                    }
                }
            }
        }
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

    fn find_child_by_kind<'a>(&self, node: &'a Node, kind: &str) -> Option<Node<'a>> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == kind {
                    return Some(child);
                }
            }
        }
        None
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
