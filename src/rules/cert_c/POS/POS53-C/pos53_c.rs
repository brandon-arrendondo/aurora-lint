//! POS53-C: Do not use more than one mutex for concurrent waiting operations on a condition variable
//!
//! This rule detects violations where the same condition variable is used with
//! different mutexes in pthread_cond_wait() or pthread_cond_timedwait() calls.
//!
//! ## Problem
//! Using multiple different mutexes with the same condition variable creates
//! undefined behavior. The POSIX standard states: "the effect of an attempt by
//! any thread to wait on that condition variable using a different mutex is undefined."
//!
//! ## Examples
//!
//! **Non-compliant:**
//! ```c
//! pthread_cond_t cv;
//! pthread_mutex_t mutex1, mutex2;
//!
//! void waiter1() {
//!     pthread_cond_wait(&cv, &mutex1);  // Using mutex1
//! }
//!
//! void waiter2() {
//!     pthread_cond_wait(&cv, &mutex2);  // Using mutex2 - VIOLATION!
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! pthread_cond_t cv;
//! pthread_mutex_t mutex1;
//!
//! void waiter1() {
//!     pthread_cond_wait(&cv, &mutex1);  // Using mutex1
//! }
//!
//! void waiter2() {
//!     pthread_cond_wait(&cv, &mutex1);  // Using same mutex1 - OK
//! }
//! ```
//!
//! ## Detection Strategy
//! - Track all pthread_cond_wait() and pthread_cond_timedwait() calls
//! - For each call, extract condition variable (arg 0) and mutex (arg 1)
//! - Build a map: condition_variable → set of mutexes
//! - Report violation if any condition variable has more than one mutex

use crate::manifest::{RuleCategory, Severity};
use crate::prelude::RuleViolation;
use crate::rules::cert_c::CertRule;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Pos53C;

impl CertRule for Pos53C {
    fn rule_id(&self) -> &'static str {
        "POS53-C"
    }

    fn cert_id(&self) -> &'static str {
        "POS53"
    }

    fn description(&self) -> &'static str {
        "Do not use more than one mutex for concurrent waiting operations on a condition variable"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // A condition variable identifier can legitimately name two different
        // objects: a file-scope global (the intended, shared-across-threads
        // case this rule targets) or a function-local variable that happens
        // to share a name with an unrelated local in some other function.
        // Aggregating call sites for the latter case file-wide would falsely
        // merge two unrelated cv/mutex pairs into one "multiple mutexes"
        // finding. So: track file-scope cond vars globally (correct - they
        // really are the same object everywhere), but track function-local
        // cond vars per function_definition, mirroring the per-scope reset
        // pattern used by EXP39-C.
        let global_cond_vars = self.collect_global_cond_var_names(node, source);

        let functions = query::find_descendants_of_kinds(*node, &["function_definition"]);

        if functions.is_empty() {
            // No functions at all - fall back to whole-translation-unit
            // scoping, matching pre-fix behavior for this edge case.
            let mut cond_var_to_mutexes: HashMap<String, HashSet<String>> = HashMap::new();
            let mut cond_var_locations: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
            self.collect_cond_wait_calls(
                node,
                source,
                &mut cond_var_to_mutexes,
                &mut cond_var_locations,
            );
            self.report_violations(&cond_var_to_mutexes, &cond_var_locations, &mut violations);
        } else {
            // File-scope cond vars are genuinely shared across every
            // function, so accumulate their mutex sets across all functions
            // before checking.
            let mut global_cond_var_to_mutexes: HashMap<String, HashSet<String>> = HashMap::new();
            let mut global_cond_var_locations: HashMap<String, Vec<(usize, usize)>> =
                HashMap::new();

            for func in &functions {
                // Local (per-function) tracking maps - reset for every
                // function so same-named locals in different functions are
                // never aggregated together.
                let mut local_cond_var_to_mutexes: HashMap<String, HashSet<String>> =
                    HashMap::new();
                let mut local_cond_var_locations: HashMap<String, Vec<(usize, usize)>> =
                    HashMap::new();

                self.collect_cond_wait_calls(
                    func,
                    source,
                    &mut local_cond_var_to_mutexes,
                    &mut local_cond_var_locations,
                );

                for (cond_var, mutexes) in local_cond_var_to_mutexes {
                    let locations = local_cond_var_locations
                        .remove(&cond_var)
                        .unwrap_or_default();
                    if global_cond_vars.contains(&cond_var) {
                        global_cond_var_to_mutexes
                            .entry(cond_var.clone())
                            .or_default()
                            .extend(mutexes);
                        global_cond_var_locations
                            .entry(cond_var)
                            .or_default()
                            .extend(locations);
                    } else {
                        // Function-local cond var: check within this
                        // function's scope only.
                        let mut this_fn_map = HashMap::new();
                        this_fn_map.insert(cond_var.clone(), mutexes);
                        let mut this_fn_locations = HashMap::new();
                        this_fn_locations.insert(cond_var, locations);
                        self.report_violations(&this_fn_map, &this_fn_locations, &mut violations);
                    }
                }
            }

            self.report_violations(
                &global_cond_var_to_mutexes,
                &global_cond_var_locations,
                &mut violations,
            );
        }

        violations
    }
}

impl Pos53C {
    /// Report violations for condition variables used with multiple mutexes
    /// within a given tracking scope (either file-scope aggregation or a
    /// single function's local scope).
    fn report_violations(
        &self,
        cond_var_to_mutexes: &HashMap<String, HashSet<String>>,
        cond_var_locations: &HashMap<String, Vec<(usize, usize)>>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for (cond_var, mutexes) in cond_var_to_mutexes {
            if mutexes.len() > 1 {
                // Found a violation - same condition variable with multiple mutexes
                if let Some(locations) = cond_var_locations.get(cond_var) {
                    if let Some(&(row, column)) = locations.first() {
                        let mutex_list: Vec<&String> = mutexes.iter().collect();

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Medium,
                            message: format!(
                                "Condition variable '{}' is used with multiple different mutexes: {}. \
                                All threads waiting on a condition variable must use the same mutex.",
                                cond_var,
                                mutex_list
                                    .iter()
                                    .map(|s| format!("'{}'", s))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ),
                            file_path: String::new(),
                            line: row + 1,
                            column: column + 1,
                            suggestion: Some(
                                "Use the same mutex for all pthread_cond_wait() and pthread_cond_timedwait() calls on this condition variable, or use separate condition variables for different mutexes."
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// Collect the names of condition variable expressions declared at file
    /// scope (i.e. as a top-level `declaration`, not inside any function
    /// body). These are genuinely shared objects across every function that
    /// references them, unlike function-local declarations of the same
    /// name, so it is correct to merge their pthread_cond_wait call sites
    /// into a single file-wide bucket.
    ///
    /// The tracking maps in `collect_cond_wait_calls` key on the raw
    /// argument text (e.g. `&cv`), so this returns names in that same
    /// `&name` form for direct comparison.
    fn collect_global_cond_var_names(&self, node: &Node, source: &str) -> HashSet<String> {
        let mut names = HashSet::new();
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "declaration" {
                    let has_cond_t = query::find_descendants_of_kind(child, "type_identifier")
                        .iter()
                        .any(|t| get_node_text(t, source).trim() == "pthread_cond_t");
                    if !has_cond_t {
                        continue;
                    }
                    for name in self.collect_declared_names(&child, source) {
                        names.insert(format!("&{}", name));
                        names.insert(name);
                    }
                }
            }
        }
        names
    }

    /// Collect the identifier names introduced by a `declaration` node
    /// (handles plain identifiers and init_declarators).
    fn collect_declared_names(&self, decl: &Node, source: &str) -> Vec<String> {
        let mut names = Vec::new();
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                match child.kind() {
                    "identifier" => {
                        names.push(get_node_text(&child, source).trim().to_string());
                    }
                    "init_declarator" => {
                        if let Some(declarator) = child.child_by_field_name("declarator") {
                            if declarator.kind() == "identifier" {
                                names.push(get_node_text(&declarator, source).trim().to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        names
    }

    fn collect_cond_wait_calls(
        &self,
        node: &Node,
        source: &str,
        cond_var_to_mutexes: &mut HashMap<String, HashSet<String>>,
        cond_var_locations: &mut HashMap<String, Vec<(usize, usize)>>,
    ) {
        // Check if this is a call_expression
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = n.child_by_field_name("function") {
                let func_name = get_node_text(&function, source).trim();

                // Check if it's pthread_cond_wait or pthread_cond_timedwait
                if func_name == "pthread_cond_wait" || func_name == "pthread_cond_timedwait" {
                    // Extract arguments
                    if let Some(arguments) = n.child_by_field_name("arguments") {
                        let args = self.extract_arguments(&arguments, source);

                        // We need at least 2 arguments (condition_var, mutex)
                        if args.len() >= 2 {
                            let cond_var = get_node_text(&args[0], source).trim().to_string();
                            let mutex = get_node_text(&args[1], source).trim().to_string();

                            // Track this combination
                            cond_var_to_mutexes
                                .entry(cond_var.clone())
                                .or_default()
                                .insert(mutex);

                            // Track location for violation reporting
                            let start_point = n.start_position();
                            cond_var_locations
                                .entry(cond_var)
                                .or_default()
                                .push((start_point.row, start_point.column));
                        }
                    }
                }
            }
        }
    }

    fn extract_arguments<'a>(&self, arguments: &'a Node, _source: &str) -> Vec<Node<'a>> {
        let mut args = Vec::new();
        let mut cursor = arguments.walk();

        for child in arguments.children(&mut cursor) {
            // Skip parentheses and commas
            if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                args.push(child);
            }
        }

        args
    }
}
