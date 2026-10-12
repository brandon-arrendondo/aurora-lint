// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! CON34-C: Declare objects shared between threads with appropriate storage durations
//!
//! Accessing the automatic or thread-local variables of one thread from another thread
//! is undefined behavior and can cause invalid memory accesses. When variables are
//! shared between threads, they must have:
//! - Static storage duration (static variables)
//! - Allocated storage duration (heap-allocated via malloc/calloc)
//!
//! Do NOT share:
//! - Automatic storage duration (local/stack variables)
//! - Thread-specific storage (tss_t) without proper synchronization
//!
//! ## Examples:
//!
//! **Non-compliant (Automatic Storage Duration):**
//! ```c
//! void create_thread(thrd_t *tid, int *val) {
//!   if (thrd_success != thrd_create(tid, child_thread, val)) {
//!     /* Handle error */
//!   }
//! }
//!
//! int main(void) {
//!   int val = 1;  // Automatic (local) variable
//!   thrd_t tid;
//!   create_thread(&tid, &val);  // Passing address of local variable to thread
//!   if (thrd_success != thrd_join(tid, NULL)) {
//!     /* Handle error */
//!   }
//!   return 0;
//! }
//! ```
//!
//! **Compliant (Static Storage Duration):**
//! ```c
//! void create_thread(thrd_t *tid) {
//!   static int val = 1;  // Static storage - safe to share
//!   if (thrd_success != thrd_create(tid, child_thread, &val)) {
//!     /* Handle error */
//!   }
//! }
//! ```
//!
//! **Compliant (Allocated Storage Duration):**
//! ```c
//! int main(void) {
//!   thrd_t tid;
//!   int *value = (int *)malloc(sizeof(int));  // Heap allocation
//!   if (!value) {
//!     /* Handle error */
//!   }
//!   create_thread(&tid, value);
//!   if (thrd_success != thrd_join(tid, NULL)) {
//!     /* Handle error */
//!   }
//!   free(value);
//!   return 0;
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find thread creations by their thread-API contract
//!   (`thread_api::thread_op`): C11, POSIX and any declared family
//! - Report one whose argument is the address of an automatic or
//!   thread-local object (`thread_storage::passed_object`, the analysis
//!   POS50-C shares), however the thread is joined afterwards: CERT reports
//!   the sharing itself, not a lifetime overrun
//! - For C11 `thrd_create()`, also presume that a pointer parameter or a
//!   non-static name not allocated in the function may reference automatic
//!   storage
//! - Find `tss_set()` (or a declared family's) in a function that also
//!   creates a thread and reads no value back with `tss_get()`
//! - OpenMP parallel regions sharing a local without `private`, and calls to
//!   library functions with internal static storage

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::settings::threads::{Role, ThreadOpKind};
use crate::utility::cert_c::ast_utils::{
    self, find_containing_function, get_function_parameters, get_identifier_from_declarator,
    get_node_text, is_pointer_type,
};
use crate::utility::cert_c::call_roles;
use crate::utility::cert_c::thread_api::{self, Family, ProjectFunctions, ThreadCall};
use crate::utility::cert_c::thread_storage::{self, SharedStorage};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use tree_sitter::Node;

#[derive(Default)]
pub struct Con34C {
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
}

impl CertRule for Con34C {
    fn rule_id(&self) -> &'static str {
        "CON34-C"
    }

    fn description(&self) -> &'static str {
        "Declare objects shared between threads with appropriate storage durations"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "CON34-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

/// Functions that use internal static storage and are not thread-safe.
/// Each entry is (function_name, thread-safe_alternative).
const THREAD_UNSAFE_FUNCTIONS: &[(&str, &str)] = &[
    ("localtime", "localtime_r"),
    ("gmtime", "gmtime_r"),
    ("ctime", "ctime_r"),
    ("asctime", "asctime_r"),
    ("strtok", "strtok_r"),
    ("rand", "rand_r or a thread-local PRNG"),
    ("getenv", "secure_getenv or a cached copy"),
    ("strerror", "strerror_r"),
    ("readdir", "readdir_r"),
    ("tmpnam", "mkstemp"),
    ("setlocale", "uselocale"),
    ("inet_ntoa", "inet_ntop"),
    ("gethostbyname", "getaddrinfo"),
    ("gethostbyaddr", "getnameinfo"),
];

/// `ast_utils::get_identifier_from_declarator` as an `Option`, matching the
/// call shape the rest of this file wants. NOT the same as
/// `ast_utils::find_identifier_in_declarator`: that function only searches a
/// declarator's *children* for an identifier, so it misses the extremely
/// common case where the declarator field itself already IS a bare
/// `identifier` node (`int j = 0;`, no pointer/array wrapper) --
/// `get_identifier_from_declarator` handles that case by matching on the
/// node's own kind first.
fn declarator_identifier(declarator: &Node, source: &str) -> Option<String> {
    let name = get_identifier_from_declarator(declarator, source);
    (!name.is_empty()).then_some(name)
}

impl Con34C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let project = self.project.borrow();
        let project = project.as_ref();
        for n in query::find_descendants_of_kinds(*node, &["call_expression", "compound_statement"])
        {
            if n.kind() == "call_expression" {
                match thread_api::thread_op(&n, source, project) {
                    Some(call) if call.kind() == ThreadOpKind::ThreadCreate => {
                        self.check_thread_create_call(&n, &call, source, violations);
                    }
                    Some(call) if call.kind() == ThreadOpKind::TssSet => {
                        self.check_tss_set_call(&n, source, project, violations);
                    }
                    Some(_) => {}
                    None => {
                        if let Some(func) = n.child_by_field_name("function") {
                            let func_name = get_node_text(&func, source);
                            self.check_thread_unsafe_call(func_name, &n, violations);
                        }
                    }
                }
            }

            // Check for OpenMP parallel regions
            if n.kind() == "compound_statement" {
                self.check_openmp_parallel_region(&n, source, violations);
            }
        }
    }

    fn check_thread_create_call(
        &self,
        call_node: &Node,
        create: &ThreadCall,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let message = if let Some(passed) = thread_storage::passed_object(create, source) {
            let storage = match passed.storage {
                SharedStorage::Automatic => "automatic (local)",
                SharedStorage::ThreadLocal => "thread-local",
            };
            format!(
                "Passing address of {storage} variable '{}' to {}()",
                passed.name, create.name
            )
        } else if create.family == Family::C11 {
            // The presumptive form: a pointer whose storage this function
            // cannot see.
            let Some(arg_node) = create.operand(Role::Arg) else {
                return;
            };
            let arg_text = get_node_text(&arg_node, source);
            let presumed = (self.is_pointer_parameter(&arg_node, source, call_node)
                && !self.is_allocated_pointer(arg_text, call_node, source)
                && !self.is_likely_allocated_param(arg_text))
                || (arg_node.kind() == "identifier"
                    && !self.is_static_variable(&arg_node, arg_text, source)
                    && !self.is_allocated_pointer(arg_text, call_node, source)
                    && !self.is_likely_allocated_param(arg_text)
                    && !arg_text.starts_with('&'));
            if !presumed {
                return;
            }
            format!(
                "Passing '{}' to {}() may reference automatic storage",
                arg_text, create.name
            )
        } else {
            return;
        };

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::Medium,
            message,
            file_path: String::new(),
            line: call_node.start_position().row + 1,
            column: call_node.start_position().column + 1,
            suggestion: Some(
                "Use static or heap-allocated storage for data shared between threads".to_string(),
            ),
            ..Default::default()
        });
    }

    fn check_tss_set_call(
        &self,
        call_node: &Node,
        source: &str,
        project: Option<&ProjectFunctions>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // tss_set() within a function that also calls thrd_create() is problematic
        // ONLY if the value being set is not retrieved with tss_get before passing to the thread

        // Find the enclosing function
        if let Some(function) = find_containing_function(call_node) {
            // Check if this function also creates threads
            if Self::performs(&function, source, project, ThreadOpKind::ThreadCreate) {
                // Check if there's a tss_get between tss_set and thrd_create
                // If tss_get is used to retrieve the value before passing to thread, it's compliant
                if Self::performs(&function, source, project, ThreadOpKind::TssGet) {
                    // This is compliant - using tss_get to retrieve allocated storage
                    return;
                }

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Medium,
                    message: "Thread-specific storage (tss_set) used in function that creates threads. Child thread may access parent's thread-specific data".to_string(),
                    file_path: String::new(),
                    line: call_node.start_position().row + 1,
                    column: call_node.start_position().column + 1,
                    suggestion: Some(
                        "Use static or allocated storage for data shared between threads".to_string()
                    ),
                    ..Default::default()
                });
            }
        }
    }

    fn is_pointer_parameter(&self, node: &Node, source: &str, context: &Node) -> bool {
        // Extract the base identifier from the node (might be wrapped in casts, etc.)
        let var_name = self.extract_base_identifier(node, source);

        if let Some(var_name) = var_name {
            // Find the enclosing function
            if let Some(function) = find_containing_function(context) {
                // Check if this is a pointer parameter
                if let Some(params) = get_function_parameters(&function, source) {
                    return params
                        .iter()
                        .any(|(name, ptype)| name == &var_name && is_pointer_type(ptype));
                }
            }
        }

        false
    }

    #[allow(clippy::only_used_in_recursion)]
    fn extract_base_identifier(&self, node: &Node, source: &str) -> Option<String> {
        // Handle direct identifiers
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source).to_string());
        }

        // Handle cast expressions: (type)var
        if node.kind() == "cast_expression" {
            if let Some(value) = node.child_by_field_name("value") {
                return self.extract_base_identifier(&value, source);
            }
        }

        // Handle parenthesized expressions: (var)
        if node.kind() == "parenthesized_expression" {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() != "(" && child.kind() != ")" {
                        return self.extract_base_identifier(&child, source);
                    }
                }
            }
        }

        // Recursively search for identifier in child nodes
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "identifier" {
                    return Some(get_node_text(&child, source).to_string());
                }
            }
        }

        None
    }

    fn is_allocated_pointer(&self, var_name: &str, context: &Node, source: &str) -> bool {
        // Check if this pointer was assigned from malloc/calloc in the current function
        if let Some(function) = find_containing_function(context) {
            if let Some(body) = function.child_by_field_name("body") {
                return self.find_malloc_assignment(&body, var_name, source);
            }
        }
        false
    }

    /// True if `ident_node` (occurrence of `var_name`) resolves to a `static`
    /// declaration -- either the enclosing function's local static, or a
    /// file-scope global. Uses `ast_utils::find_enclosing_declaration_for_identifier`
    /// (scope/shadowing-aware) instead of a raw text search, which could
    /// match an unrelated declaration of the same name in a different
    /// function, or an ordinary comment/string mentioning "static name".
    fn is_static_variable(&self, ident_node: &Node, var_name: &str, source: &str) -> bool {
        if let Some(decl) =
            ast_utils::find_enclosing_declaration_for_identifier(ident_node, var_name, source)
        {
            return Self::declaration_is_static(&decl, source);
        }
        // Fallback for file-scope (global) declarations, which
        // `find_enclosing_declaration_for_identifier` intentionally does not
        // resolve to (it only walks enclosing `compound_statement` blocks).
        ast_utils::find_global_declaration_for_identifier(ident_node, var_name, source)
            .is_some_and(|decl| Self::declaration_is_static(&decl, source))
    }

    /// True if a `declaration` node carries the `static` storage-class specifier.
    fn declaration_is_static(decl: &Node, source: &str) -> bool {
        ast_utils::declaration_has_storage_class(decl, "static", source)
    }

    fn is_likely_allocated_param(&self, var_name: &str) -> bool {
        // Heuristic: parameters named 'value', 'v', 'data', 'buffer', 'mem' are often heap-allocated
        // This is a pragmatic workaround for lack of inter-procedural analysis
        matches!(
            var_name,
            "value" | "v" | "data" | "buffer" | "mem" | "ptr" | "p"
        )
    }

    fn find_malloc_assignment(&self, node: &Node, var_name: &str, source: &str) -> bool {
        // Find the first node that either assigns to var_name or declares it with
        // an initializer, matching the same node exactly like the original
        // recursive walk (which stopped the entire search at the first such node,
        // regardless of whether that particular node turned out to be an
        // allocation call).
        let candidate = query::find_first_descendant(*node, |n| {
            if n.kind() == "assignment_expression" {
                if let Some(left) = n.child_by_field_name("left") {
                    if get_node_text(&left, source) == var_name {
                        return true;
                    }
                }
                return false;
            }

            if n.kind() == "init_declarator" {
                if let Some(declarator) = n.child_by_field_name("declarator") {
                    if let Some(name) = declarator_identifier(&declarator, source) {
                        if name == var_name {
                            return true;
                        }
                    }
                }
            }

            false
        });

        match candidate {
            Some(n) if n.kind() == "assignment_expression" => n
                .child_by_field_name("right")
                .map(|right| self.is_allocation_call(&right, source))
                .unwrap_or(false),
            Some(n) => n
                .child_by_field_name("value")
                .map(|value| self.is_allocation_call(&value, source))
                .unwrap_or(false),
            None => false,
        }
    }

    #[allow(clippy::only_used_in_recursion)]
    fn is_allocation_call(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                let func_name = get_node_text(&func, source);
                return call_roles::is_allocator_call(func_name);
            }
        }

        // Handle cast expressions: (type*)malloc(...)
        if node.kind() == "cast_expression" {
            if let Some(value) = node.child_by_field_name("value") {
                return self.is_allocation_call(&value, source);
            }
        }

        false
    }

    /// Whether `function`'s body performs a thread operation of `kind`.
    fn performs(
        function: &Node,
        source: &str,
        project: Option<&ProjectFunctions>,
        kind: ThreadOpKind,
    ) -> bool {
        function.child_by_field_name("body").is_some_and(|body| {
            query::find_descendants_of_kind(body, "call_expression")
                .iter()
                .any(|call| thread_api::thread_op_of_kind(call, source, project, kind).is_some())
        })
    }

    fn check_openmp_parallel_region(
        &self,
        compound_stmt: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check if this compound statement is preceded by an OpenMP parallel pragma
        let start_byte = compound_stmt.start_byte();

        // Check the source text before this compound statement for #pragma omp parallel
        if start_byte > 0 {
            // Look back up to 200 bytes for the pragma; snap to char boundary
            let preceding_text =
                crate::utility::cert_c::text_bounds::suffix_at_most(&source[..start_byte], 200);

            // Check if this section contains an OpenMP parallel pragma without private clause
            if preceding_text.contains("#pragma omp parallel")
                && !preceding_text.contains("private(")
            {
                // Make sure the pragma is close to this compound statement (not from earlier code)
                let lines: Vec<&str> = preceding_text.lines().collect();
                if let Some(last_few_lines) = lines.iter().rev().take(3).find(|line| {
                    let trimmed = line.trim();
                    trimmed.starts_with("#pragma omp parallel")
                }) {
                    // Found the pragma close to this block
                    if !last_few_lines.contains("private(") {
                        self.check_parallel_region_variables(compound_stmt, source, violations);
                    }
                }
            }
        }
    }

    fn check_parallel_region_variables(
        &self,
        region: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Find variables declared outside this parallel region that are accessed inside
        // For simplicity, look for common patterns like j++ in loops

        // Get the function containing this region
        if let Some(function) = find_containing_function(region) {
            // Get function-local variables
            let local_vars = self.find_local_vars_before_node(&function, region, source);

            // Check if any of these are modified in the parallel region
            for var in &local_vars {
                if self.is_var_modified_in_node(region, var, source) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Medium,
                        message: format!(
                            "Variable '{}' is shared between threads in OpenMP parallel region without private clause",
                            var
                        ),
                        file_path: String::new(),
                        line: region.start_position().row + 1,
                        column: region.start_position().column + 1,
                        suggestion: Some(
                            format!("Add 'private({})' to the #pragma omp parallel directive", var)
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    fn find_local_vars_before_node(
        &self,
        function: &Node,
        before_node: &Node,
        source: &str,
    ) -> Vec<String> {
        let mut vars = Vec::new();

        if let Some(body) = function.child_by_field_name("body") {
            let target_start = before_node.start_byte();
            self.collect_local_vars_before(&body, target_start, source, &mut vars);
        }

        vars
    }

    fn collect_local_vars_before(
        &self,
        node: &Node,
        before_byte: usize,
        source: &str,
        vars: &mut Vec<String>,
    ) {
        // Explicit-stack walk: pruning is by byte position, not node kind, so
        // substrate::query::find_descendants (kind-based, no positional skip)
        // can't express this. A plain recursive walk here can stack-overflow
        // on pathologically deep-nested statement prefixes (e.g. hostap-style
        // nested if/else chains), so we thread our own stack instead.
        let mut stack = vec![*node];

        while let Some(current) = stack.pop() {
            // Don't traverse into the target node itself
            if current.start_byte() >= before_byte {
                continue;
            }

            if current.kind() == "declaration" {
                // Check if it's NOT static
                let mut is_static = false;
                let mut var_names = Vec::new();

                for i in 0..current.child_count() {
                    if let Some(child) = current.child(i) {
                        if child.kind() == "storage_class_specifier"
                            && get_node_text(&child, source) == "static"
                        {
                            is_static = true;
                        }

                        if child.kind() == "init_declarator" {
                            if let Some(declarator) = child.child_by_field_name("declarator") {
                                if let Some(name) = declarator_identifier(&declarator, source) {
                                    var_names.push(name);
                                }
                            }
                        }
                    }
                }

                if !is_static {
                    vars.extend(var_names);
                }
            }

            // Push children in reverse so they're visited in original order
            for i in (0..current.child_count()).rev() {
                if let Some(child) = current.child(i) {
                    stack.push(child);
                }
            }
        }
    }

    fn is_var_modified_in_node(&self, node: &Node, var_name: &str, source: &str) -> bool {
        // Check for assignment or update expressions involving this variable
        query::find_first_descendant(*node, |n| {
            matches!(n.kind(), "update_expression" | "assignment_expression")
                && get_node_text(&n, source).contains(var_name)
        })
        .is_some()
    }

    fn check_thread_unsafe_call(
        &self,
        func_name: &str,
        call_node: &Node,
        violations: &mut Vec<RuleViolation>,
    ) {
        for &(unsafe_fn, alternative) in THREAD_UNSAFE_FUNCTIONS {
            if func_name == unsafe_fn {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "'{}()' uses internal static storage that is shared between threads",
                        func_name
                    ),
                    file_path: String::new(),
                    line: call_node.start_position().row + 1,
                    column: call_node.start_position().column + 1,
                    suggestion: Some(format!("Use '{}' instead for thread safety", alternative)),
                    ..Default::default()
                });
                return;
            }
        }
    }
}
