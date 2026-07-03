//! CON06-C: Ensure that every mutex outlives the data it protects
//!
//! This rule detects cases where a mutex may not outlive the data it protects,
//! which can lead to data races or undefined behavior.
//!
//! Key violation patterns:
//! 1. Local (stack) mutex protecting heap-allocated or static data
//! 2. Mutex destroyed (mtx_destroy/pthread_mutex_destroy) before protected data is freed
//!
//! Noncompliant pattern:
//!   void bad_func(void) {
//!       mtx_t local_mutex;           // Stack-allocated mutex
//!       mtx_init(&local_mutex, mtx_plain);
//!       shared_data = malloc(100);   // Heap data outlives mutex
//!       mtx_destroy(&local_mutex);   // Mutex destroyed, data still exists
//!   }
//!
//! Compliant pattern:
//!   static mtx_t global_mutex;       // Static mutex matches data lifetime
//!   void good_func(void) {
//!       mtx_init(&global_mutex, mtx_plain);
//!       shared_data = malloc(100);
//!       // ... use data ...
//!       free(shared_data);
//!       mtx_destroy(&global_mutex);  // Proper order
//!   }

use crate::manifest::{RuleCategory, Severity};
use crate::rules::{CertRule, RuleViolation};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Con06C;

impl CertRule for Con06C {
    fn rule_id(&self) -> &'static str {
        "CON06-C"
    }

    fn description(&self) -> &'static str {
        "Ensure that every mutex outlives the data it protects"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "CON06-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        for func_node in query::find_descendants_of_kind(*node, "function_definition") {
            self.analyze_function(&func_node, source, &mut violations);
        }
        violations
    }
}

impl Con06C {
    fn analyze_function(
        &self,
        function_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(body) = function_node.child_by_field_name("body") {
            // Track local mutex declarations
            let mut local_mutexes: HashMap<String, Node> = HashMap::new();
            // Track static/global mutex declarations
            let mut static_mutexes: HashSet<String> = HashSet::new();
            // Track heap allocations that might be protected by mutexes
            let mut heap_allocations: HashMap<String, Node> = HashMap::new();
            // Track mutex destroy calls
            let mut mutex_destroys: Vec<(String, Node)> = Vec::new();
            // Track free calls
            let mut free_calls: Vec<(String, Node)> = Vec::new();

            self.collect_declarations(&body, source, &mut local_mutexes, &mut static_mutexes);
            self.collect_heap_ops(&body, source, &mut heap_allocations, &mut free_calls);
            self.collect_mutex_destroys(&body, source, &mut mutex_destroys);

            // Check pattern 1: Local mutex with heap allocation but no free before destroy
            for (mutex_name, mutex_node) in &local_mutexes {
                // If there's heap allocation in the function and local mutex
                if !heap_allocations.is_empty() {
                    // Check if mutex is destroyed before any heap data
                    for (destroy_mutex, destroy_node) in &mutex_destroys {
                        if destroy_mutex == mutex_name {
                            // Check if any heap allocation is not freed before mutex destroy
                            for (alloc_var, alloc_node) in &heap_allocations {
                                let freed_before_destroy =
                                    free_calls.iter().any(|(free_var, free_node)| {
                                        free_var == alloc_var
                                            && free_node.start_byte() < destroy_node.start_byte()
                                    });

                                if !freed_before_destroy
                                    && alloc_node.start_byte() < destroy_node.start_byte()
                                {
                                    let start_point = mutex_node.start_position();
                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        severity: Severity::Medium,
                                        message: format!(
                                            "Local mutex '{}' may not outlive heap-allocated data '{}'. \
                                            Heap data should be freed before mutex is destroyed.",
                                            mutex_name, alloc_var
                                        ),
                                        file_path: String::new(),
                                        line: start_point.row + 1,
                                        column: start_point.column + 1,
                                        suggestion: Some(
                                            "Use a static/global mutex for data with longer lifetime, \
                                            or ensure data is freed before mutex is destroyed.".to_string()
                                        ),
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // Check pattern 2: Mutex destroy before corresponding free
            for (destroy_mutex, destroy_node) in &mutex_destroys {
                for (free_var, free_node) in &free_calls {
                    // If free happens AFTER destroy, the mutex doesn't outlive the data
                    if free_node.start_byte() > destroy_node.start_byte() {
                        // Only flag if the variables seem related (heuristic: in same function)
                        if local_mutexes.contains_key(destroy_mutex) {
                            let start_point = destroy_node.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::Medium,
                                message: format!(
                                    "Mutex '{}' destroyed before protected data '{}' is freed. \
                                    The mutex should outlive the data it protects.",
                                    destroy_mutex, free_var
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some(
                                    "Reorder operations: free the protected data before destroying the mutex.".to_string()
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    fn collect_declarations<'a>(
        &self,
        node: &Node<'a>,
        source: &str,
        local_mutexes: &mut HashMap<String, Node<'a>>,
        static_mutexes: &mut HashSet<String>,
    ) {
        for decl_node in query::find_descendants_of_kind(*node, "declaration") {
            let decl_text = get_node_text(&decl_node, source);
            let is_static = decl_text.starts_with("static ");

            // Check if this is a mutex declaration (mtx_t or pthread_mutex_t)
            if decl_text.contains("mtx_t") || decl_text.contains("pthread_mutex_t") {
                // Extract variable name
                if let Some(declarator) = decl_node.child_by_field_name("declarator") {
                    let var_name = self.extract_identifier(&declarator, source);
                    if !var_name.is_empty() {
                        if is_static {
                            static_mutexes.insert(var_name);
                        } else {
                            local_mutexes.insert(var_name, decl_node);
                        }
                    }
                }
            }
        }
    }

    fn collect_heap_ops<'a>(
        &self,
        node: &Node<'a>,
        source: &str,
        heap_allocations: &mut HashMap<String, Node<'a>>,
        free_calls: &mut Vec<(String, Node<'a>)>,
    ) {
        // Look for assignment expressions with malloc/calloc/realloc
        for op_node in
            query::find_descendants_of_kinds(*node, &["assignment_expression", "init_declarator"])
        {
            let node_text = get_node_text(&op_node, source);
            if node_text.contains("malloc(")
                || node_text.contains("calloc(")
                || node_text.contains("realloc(")
            {
                // Extract the variable being assigned
                if let Some(left) = op_node.child_by_field_name("left") {
                    let var_name = get_node_text(&left, source).to_string();
                    heap_allocations.insert(var_name, op_node);
                } else if let Some(declarator) = op_node.child_by_field_name("declarator") {
                    let var_name = self.extract_identifier(&declarator, source);
                    if !var_name.is_empty() {
                        heap_allocations.insert(var_name, op_node);
                    }
                }
            }
        }

        // Look for free() calls
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call_node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                if func_name == "free" {
                    if let Some(args) = call_node.child_by_field_name("arguments") {
                        // Get first argument
                        for i in 0..args.child_count() {
                            if let Some(arg) = args.child(i) {
                                if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                                    let var_name = get_node_text(&arg, source).to_string();
                                    free_calls.push((var_name, call_node));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn collect_mutex_destroys<'a>(
        &self,
        node: &Node<'a>,
        source: &str,
        mutex_destroys: &mut Vec<(String, Node<'a>)>,
    ) {
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call_node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                if func_name == "mtx_destroy" || func_name == "pthread_mutex_destroy" {
                    if let Some(args) = call_node.child_by_field_name("arguments") {
                        // Get first argument (mutex pointer)
                        for i in 0..args.child_count() {
                            if let Some(arg) = args.child(i) {
                                if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                                    let arg_text = get_node_text(&arg, source);
                                    // Remove leading & for address-of operator
                                    let var_name =
                                        arg_text.strip_prefix('&').unwrap_or(arg_text).to_string();
                                    mutex_destroys.push((var_name, call_node));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[allow(clippy::only_used_in_recursion)]
    fn extract_identifier(&self, node: &Node, source: &str) -> String {
        if node.kind() == "identifier" {
            return get_node_text(node, source).to_string();
        }
        // Handle pointer declarators
        if node.kind() == "pointer_declarator" {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    let result = self.extract_identifier(&child, source);
                    if !result.is_empty() {
                        return result;
                    }
                }
            }
        }
        // Recurse
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "identifier" {
                    return get_node_text(&child, source).to_string();
                }
            }
        }
        String::new()
    }
}
