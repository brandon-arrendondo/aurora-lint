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

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{get_identifier_from_declarator, get_node_text};
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Con07C;

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

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "CON07-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First pass: collect static variables
        let static_vars = self.collect_static_variables(node, source);

        // Second pass: check for non-atomic compound operations on these variables
        self.check_node(node, source, &static_vars, &mut violations);

        violations
    }
}

impl Con07C {
    /// Collect all static variable names from the translation unit
    fn collect_static_variables(&self, node: &Node, source: &str) -> Vec<String> {
        let mut static_vars = Vec::new();
        self.find_static_variables(node, source, &mut static_vars);
        static_vars
    }

    fn find_static_variables(&self, node: &Node, source: &str, static_vars: &mut Vec<String>) {
        for decl_node in query::find_descendants_of_kind(*node, "declaration") {
            let mut is_static = false;
            let mut is_file_scope = decl_node
                .parent()
                .is_some_and(|p| p.kind() == "translation_unit");
            let mut is_mutex_or_thread_type = false;
            let mut var_names = Vec::new();

            for i in 0..decl_node.child_count() {
                if let Some(child) = decl_node.child(i) {
                    match child.kind() {
                        "storage_class_specifier" => {
                            if get_node_text(&child, source) == "static" {
                                is_static = true;
                            }
                            if get_node_text(&child, source) == "extern" {
                                // extern declarations are not owned by this file
                                is_file_scope = false;
                            }
                        }
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

            // Collect static variables AND file-scope globals (non-mutex types)
            if is_static || (is_file_scope && !is_mutex_or_thread_type) {
                static_vars.extend(var_names);
            }
        }
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        static_vars: &[String],
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
        static_vars: &[String],
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

        // Get function body
        let body = match function_node.child_by_field_name("body") {
            Some(b) => b,
            None => return,
        };

        // Check for compound operations on static variables
        let static_var_accesses = self.find_static_var_accesses(&body, source, static_vars);

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
            let has_compound_write = static_var_accesses
                .iter()
                .any(|v| self.has_compound_operation_on_var(&body, source, v));
            let combines_reads = self.combines_multiple_vars(&body, source, &static_var_accesses);
            let writes_multiple = self.writes_multiple_vars(&body, source, &static_var_accesses);
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
            if self.has_compound_operation_on_var(&body, source, &static_var_accesses[0]) {
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
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(func) = n.child_by_field_name("function") else {
                return false;
            };
            let func_name = get_node_text(&func, source);
            matches!(
                func_name,
                "mtx_lock"
                    | "mtx_unlock"
                    | "pthread_mutex_lock"
                    | "pthread_mutex_unlock"
                    | "stdThreadLockAcquire"
                    | "stdThreadLockRelease"
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
        static_vars: &[String],
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
        static_vars: &[String],
        accesses: &mut Vec<String>,
    ) {
        for id_node in query::find_descendants_of_kind(*node, "identifier") {
            let name = get_node_text(&id_node, source);
            if static_vars.contains(&name.to_string()) {
                accesses.push(name.to_string());
            }
        }
    }

    fn has_compound_operation_on_var(&self, node: &Node, source: &str, var_name: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() == "assignment_expression" {
                let left = n.child_by_field_name("left");
                let right = n.child_by_field_name("right");
                if let Some(left_node) = left {
                    let left_text = get_node_text(&left_node, source);
                    if left_text == var_name {
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
                            let right_text = get_node_text(&right_node, source);
                            if right_text.contains(var_name) {
                                return true;
                            }
                        }
                    }
                }
            }

            // Increment/decrement: x++, ++x, x--, --x
            if matches!(n.kind(), "update_expression") {
                if let Some(argument) = n.child_by_field_name("argument") {
                    if get_node_text(&argument, source) == var_name {
                        return true;
                    }
                }
            }

            false
        })
        .is_some()
    }

    /// Names from `vars` referenced anywhere in `node`'s subtree.
    fn vars_referenced_in(
        &self,
        node: &Node,
        source: &str,
        vars: &[String],
    ) -> std::collections::HashSet<String> {
        let mut found = std::collections::HashSet::new();
        for id_node in query::find_descendants_of_kind(*node, "identifier") {
            let name = get_node_text(&id_node, source);
            if vars.iter().any(|v| v == name) {
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
    fn combines_multiple_vars(&self, body: &Node, source: &str, vars: &[String]) -> bool {
        query::find_descendants_of_kind(*body, "binary_expression")
            .into_iter()
            .any(|expr| self.vars_referenced_in(&expr, source, vars).len() > 1)
    }

    /// True if two or more distinct shared variables are each individually
    /// written (plain assignment or an atomic store/exchange/init call)
    /// somewhere in this function — writing correlated shared state one
    /// variable at a time is not atomic as a whole, even if each
    /// individual write is.
    fn writes_multiple_vars(&self, body: &Node, source: &str, vars: &[String]) -> bool {
        let mut written = std::collections::HashSet::new();

        for assign in query::find_descendants_of_kind(*body, "assignment_expression") {
            if let Some(left) = assign.child_by_field_name("left") {
                let left_text = get_node_text(&left, source);
                if vars.iter().any(|v| v == left_text) {
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
                written.extend(self.vars_referenced_in(&first_arg, source, vars));
            }
        }

        written.len() > 1
    }
}
