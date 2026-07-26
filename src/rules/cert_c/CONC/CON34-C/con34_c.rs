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
//! - Find thrd_create() calls
//! - Check if the argument passed is an address of a local variable (&local_var)
//! - Find tss_set() calls within functions that create threads
//! - Detect if thread-specific storage is set in a parent thread but accessed by child

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Con34C;

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

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "CON34-C"
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

impl Con34C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants_of_kinds(*node, &["call_expression", "compound_statement"])
        {
            // Check for thrd_create() calls and thread-unsafe function calls
            if n.kind() == "call_expression" {
                if let Some(func) = n.child_by_field_name("function") {
                    let func_name = get_node_text(&func, source);
                    if func_name == "thrd_create" {
                        self.check_thrd_create_call(&n, source, violations);
                    } else if func_name == "tss_set" {
                        self.check_tss_set_call(&n, source, violations);
                    } else {
                        self.check_thread_unsafe_call(&func_name, &n, violations);
                    }
                }
            }

            // Check for OpenMP parallel regions
            if n.kind() == "compound_statement" {
                self.check_openmp_parallel_region(&n, source, violations);
            }
        }
    }

    fn check_thrd_create_call(
        &self,
        call_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // thrd_create(thrd_t *thr, thrd_start_t func, void *arg)
        // We need to check the third argument (arg) - the data pointer, NOT the function pointer

        if let Some(args) = call_node.child_by_field_name("arguments") {
            let mut arg_list = Vec::new();

            // Collect all non-comma arguments
            for i in 0..args.child_count() {
                if let Some(child) = args.child(i) {
                    if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                        arg_list.push(child);
                    }
                }
            }

            // We want the 3rd argument (index 2) - the data pointer
            if arg_list.len() >= 3 {
                let arg_node = arg_list[2];
                let arg_text = get_node_text(&arg_node, source);

                // Check various problematic patterns
                let is_violation = self.is_address_of_local_var(&arg_node, source, call_node)
                    || (self.is_pointer_parameter(&arg_node, source, call_node)
                        && !self.is_allocated_pointer(arg_text, call_node, source)
                        && !self.is_likely_allocated_param(arg_text))
                    || (arg_node.kind() == "identifier"
                        && !self.is_static_variable(arg_text, call_node, source)
                        && !self.is_allocated_pointer(arg_text, call_node, source)
                        && !self.is_likely_allocated_param(arg_text)
                        && !arg_text.starts_with("&"));

                if is_violation {
                    let message = if self.is_address_of_local_var(&arg_node, source, call_node) {
                        "Passing address of automatic (local) variable to thrd_create()".to_string()
                    } else {
                        format!(
                            "Passing '{}' to thrd_create() may reference automatic storage",
                            arg_text
                        )
                    };

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Medium,
                        message,
                        file_path: String::new(),
                        line: call_node.start_position().row + 1,
                        column: call_node.start_position().column + 1,
                        suggestion: Some(
                            "Use static or heap-allocated storage for data shared between threads"
                                .to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    fn check_tss_set_call(
        &self,
        call_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // tss_set() within a function that also calls thrd_create() is problematic
        // ONLY if the value being set is not retrieved with tss_get before passing to the thread

        // Find the enclosing function
        if let Some(function) = self.find_enclosing_function(call_node) {
            // Check if this function also creates threads
            if self.function_creates_threads(&function, source) {
                // Check if there's a tss_get between tss_set and thrd_create
                // If tss_get is used to retrieve the value before passing to thread, it's compliant
                if self.has_tss_get_before_thread_create(&function, source) {
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

    fn is_address_of_local_var(&self, node: &Node, source: &str, context: &Node) -> bool {
        // Check if this is a unary_expression with & operator
        if node.kind() == "unary_expression" {
            if let Some(operator) = node.child_by_field_name("operator") {
                if get_node_text(&operator, source) == "&" {
                    if let Some(argument) = node.child_by_field_name("argument") {
                        let var_name = get_node_text(&argument, source).to_string();

                        // Check if this variable is a local (automatic) variable
                        return self.is_local_variable(&var_name, context, source);
                    }
                }
            }
        }

        false
    }

    fn is_pointer_parameter(&self, node: &Node, source: &str, context: &Node) -> bool {
        // Extract the base identifier from the node (might be wrapped in casts, etc.)
        let var_name = self.extract_base_identifier(node, source);

        if let Some(var_name) = var_name {
            // Find the enclosing function
            if let Some(function) = self.find_enclosing_function(context) {
                // Check if this is a pointer parameter
                return self.is_pointer_param_of_function(&function, &var_name, source);
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
        if let Some(function) = self.find_enclosing_function(context) {
            if let Some(body) = function.child_by_field_name("body") {
                return self.find_malloc_assignment(&body, var_name, source);
            }
        }
        false
    }

    fn is_static_variable(&self, var_name: &str, _context: &Node, source: &str) -> bool {
        // This is a simplified check - ideally we'd search the whole tree
        // For now, just check if the variable name suggests it's a static/global
        source.contains(&format!("static {} ", var_name))
            || source.contains(&format!("static int *{}", var_name))
            || source.contains(&format!("static void *{}", var_name))
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
                    if let Some(name) = self.get_identifier_name(&declarator, source) {
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
                return matches!(func_name, "malloc" | "calloc" | "realloc");
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

    fn is_pointer_param_of_function(
        &self,
        function: &Node,
        param_name: &str,
        source: &str,
    ) -> bool {
        // Find the parameter list
        for i in 0..function.child_count() {
            if let Some(child) = function.child(i) {
                if child.kind() == "function_declarator" {
                    if let Some(params) = child.child_by_field_name("parameters") {
                        return self.find_pointer_parameter(&params, param_name, source);
                    }
                }
            }
        }
        false
    }

    fn find_pointer_parameter(&self, node: &Node, param_name: &str, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "parameter_declaration" {
                return false;
            }

            // Get the full text of the parameter declaration
            let param_text = get_node_text(&n, source);

            // Simple heuristic: if it contains * and the param name, it's likely a pointer parameter
            if param_text.contains('*') && param_text.contains(param_name) {
                // Double-check by finding the declarator
                if let Some(declarator) = n.child_by_field_name("declarator") {
                    if let Some(name) = self.get_identifier_name(&declarator, source) {
                        if name == param_name {
                            return true;
                        }
                    }
                }
            }

            false
        })
        .is_some()
    }

    fn is_local_variable(&self, var_name: &str, context: &Node, source: &str) -> bool {
        // Find the enclosing function
        if let Some(function) = self.find_enclosing_function(context) {
            // Look for variable declaration within this function
            if let Some(body) = function.child_by_field_name("body") {
                return self.find_local_declaration(&body, var_name, source);
            }

            // Check function parameters
            if self.is_function_parameter(&function, var_name, source) {
                return true;
            }
        }

        false
    }

    fn find_local_declaration(&self, node: &Node, var_name: &str, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "declaration" {
                return false;
            }

            // Check if it's NOT static
            let mut is_static = false;
            let mut has_var = false;

            for i in 0..n.child_count() {
                if let Some(child) = n.child(i) {
                    if child.kind() == "storage_class_specifier"
                        && get_node_text(&child, source) == "static"
                    {
                        is_static = true;
                    }

                    if child.kind() == "init_declarator" {
                        if let Some(declarator) = child.child_by_field_name("declarator") {
                            if let Some(name) = self.get_identifier_name(&declarator, source) {
                                if name == var_name {
                                    has_var = true;
                                }
                            }
                        }
                    } else if child.kind() == "identifier"
                        && get_node_text(&child, source) == var_name
                    {
                        has_var = true;
                    }
                }
            }

            // It's a local variable if it's declared here and NOT static
            has_var && !is_static
        })
        .is_some()
    }

    fn is_function_parameter(&self, function: &Node, var_name: &str, source: &str) -> bool {
        // Find the parameter list
        for i in 0..function.child_count() {
            if let Some(child) = function.child(i) {
                if child.kind() == "function_declarator" {
                    if let Some(params) = child.child_by_field_name("parameters") {
                        return self.find_parameter_name(&params, var_name, source);
                    }
                }
            }
        }
        false
    }

    fn find_parameter_name(&self, node: &Node, var_name: &str, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "parameter_declaration" {
                return false;
            }
            n.child_by_field_name("declarator")
                .and_then(|declarator| self.get_identifier_name(&declarator, source))
                .map(|name| name == var_name)
                .unwrap_or(false)
        })
        .is_some()
    }

    fn get_identifier_name(&self, node: &Node, source: &str) -> Option<String> {
        query::find_first_descendant(*node, |n| n.kind() == "identifier")
            .map(|n| get_node_text(&n, source).to_string())
    }

    fn find_enclosing_function<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        let mut current = *node;

        loop {
            if current.kind() == "function_definition" {
                return Some(current);
            }

            match current.parent() {
                Some(parent) => current = parent,
                None => return None,
            }
        }
    }

    fn function_creates_threads(&self, function: &Node, source: &str) -> bool {
        if let Some(body) = function.child_by_field_name("body") {
            return self.has_thrd_create(&body, source);
        }
        false
    }

    fn has_thrd_create(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            n.child_by_field_name("function")
                .map(|func| get_node_text(&func, source) == "thrd_create")
                .unwrap_or(false)
        })
        .is_some()
    }

    fn has_tss_get_before_thread_create(&self, function: &Node, source: &str) -> bool {
        // Check if the function uses tss_get() to retrieve the value before thrd_create
        if let Some(body) = function.child_by_field_name("body") {
            return self.has_tss_get(&body, source);
        }
        false
    }

    fn has_tss_get(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            n.child_by_field_name("function")
                .map(|func| get_node_text(&func, source) == "tss_get")
                .unwrap_or(false)
        })
        .is_some()
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
            let start_search = if start_byte > 200 {
                let mut idx = start_byte - 200;
                while !source.is_char_boundary(idx) {
                    idx += 1;
                }
                idx
            } else {
                0
            };
            let preceding_text = &source[start_search..start_byte];

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
        if let Some(function) = self.find_enclosing_function(region) {
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
                                if let Some(name) = self.get_identifier_name(&declarator, source) {
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
