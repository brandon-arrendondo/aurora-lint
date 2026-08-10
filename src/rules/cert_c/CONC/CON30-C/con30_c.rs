//! CON30-C: Clean up thread-specific storage
//!
//! Thread-specific storage (TSS) must be properly freed to avoid memory leaks.
//! When using tss_set() to store allocated memory, ensure either:
//! 1. A destructor is registered via tss_create(&key, destructor), OR
//! 2. Memory is explicitly freed via free(tss_get(key)) before thread exit
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! tss_create(&key, NULL);  // No destructor
//! int *data = malloc(sizeof(int));
//! tss_set(key, data);      // Memory leak - never freed
//! ```
//!
//! **Compliant (Destructor):**
//! ```c
//! tss_create(&key, free);  // Destructor registered
//! ```
//!
//! **Compliant (Explicit):**
//! ```c
//! free(tss_get(key));      // Explicit cleanup before thread exit
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Con30C;

/// Tracks TSS key information
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct TssKeyInfo {
    key_name: String,
    has_destructor: bool,
    create_line: usize,
    create_column: usize,
}

impl CertRule for Con30C {
    fn rule_id(&self) -> &'static str {
        "CON30-C"
    }

    fn description(&self) -> &'static str {
        "Clean up thread-specific storage"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "CON30-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // A `tss_t key;` declared at file scope is genuinely shared by every
        // function that touches it, so those keys are correctly analyzed by
        // aggregating call sites across the whole translation unit.
        let global_keys = self.collect_global_tss_key_names(node, source);

        let mut tss_keys: HashMap<String, TssKeyInfo> = HashMap::new();
        let mut tss_set_calls: HashSet<String> = HashSet::new();
        let mut tss_get_freed: HashSet<String> = HashSet::new();
        self.analyze_tss_operations(
            node,
            source,
            &mut tss_keys,
            &mut tss_set_calls,
            &mut tss_get_freed,
            Some(&global_keys),
        );
        self.collect_violations(&tss_keys, &tss_set_calls, &tss_get_freed, &mut violations);

        // A `tss_t key;` declared *inside* a function is a distinct object
        // from a same-named local in another function. Give each function
        // its own fresh scope so that one function's proper cleanup
        // (tss_create/tss_set/free(tss_get(...))) can never mask a real
        // leak of a same-named key local to a different function.
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            let mut local_keys: HashMap<String, TssKeyInfo> = HashMap::new();
            let mut local_set_calls: HashSet<String> = HashSet::new();
            let mut local_get_freed: HashSet<String> = HashSet::new();
            self.analyze_tss_operations(
                &func,
                source,
                &mut local_keys,
                &mut local_set_calls,
                &mut local_get_freed,
                None,
            );
            // Keys that are actually file-scope were already handled above
            // by the whole-translation-unit pass; don't double-report them.
            local_keys.retain(|k, _| !global_keys.contains(k));
            local_set_calls.retain(|k| !global_keys.contains(k));
            local_get_freed.retain(|k| !global_keys.contains(k));
            self.collect_violations(
                &local_keys,
                &local_set_calls,
                &local_get_freed,
                &mut violations,
            );
        }

        violations
    }
}

impl Con30C {
    /// Generate violations for keys with tss_set but no destructor and no
    /// explicit free. Shared between the file-scope (global keys) pass and
    /// the per-function (local keys) passes in `check`.
    fn collect_violations(
        &self,
        tss_keys: &HashMap<String, TssKeyInfo>,
        tss_set_calls: &HashSet<String>,
        tss_get_freed: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for (key_name, key_info) in tss_keys {
            // If tss_set was called for this key
            if tss_set_calls.contains(key_name) {
                // And no destructor was registered
                if !key_info.has_destructor {
                    // And tss_get result wasn't freed
                    if !tss_get_freed.contains(key_name) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            message: format!(
                                "Thread-specific storage key '{}' created without destructor and \
                                 memory stored via tss_set() is never freed. Register a destructor \
                                 in tss_create() or explicitly free(tss_get({})).",
                                key_name, key_name
                            ),
                            severity: self.severity(),
                            line: key_info.create_line,
                            column: key_info.create_column,
                            file_path: String::new(),
                            suggestion: Some(format!(
                                "Either register a destructor: tss_create(&{}, free) or \
                                 explicitly cleanup: free(tss_get({}))",
                                key_name, key_name
                            )),
                            requires_manual_review: None,
                        });
                    }
                }
            }
        }
    }

    /// Collect the names of `tss_t` variables declared directly at file
    /// scope (i.e. direct children of the translation unit, not inside any
    /// function body). These are genuinely shared across every function
    /// that references them, so it's correct to aggregate their call sites
    /// across the whole translation unit. Locals declared inside a function
    /// body are a different object per function and must not be merged
    /// with this set.
    fn collect_global_tss_key_names(&self, node: &Node, source: &str) -> HashSet<String> {
        let mut names = HashSet::new();
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() != "declaration" {
                    continue;
                }
                let is_tss_t = child
                    .child_by_field_name("type")
                    .map(|t| get_node_text(&t, source).trim() == "tss_t")
                    .unwrap_or(false);
                if !is_tss_t {
                    continue;
                }
                for j in 0..child.child_count() {
                    if child.field_name_for_child(j as u32) == Some("declarator") {
                        if let Some(declarator) = child.child(j) {
                            if let Some(name) = self.declarator_identifier(&declarator, source) {
                                names.insert(name);
                            }
                        }
                    }
                }
            }
        }
        names
    }

    /// Recover the identifier being declared by a (possibly wrapped)
    /// declarator node, e.g. `key` in `tss_t key;` or `tss_t key =
    /// TSS_DTOR_ITERATIONS;`.
    fn declarator_identifier(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source).to_string());
        }
        if let Some(inner) = node.child_by_field_name("declarator") {
            return self.declarator_identifier(&inner, source);
        }
        query::find_first_descendant(*node, |n| n.kind() == "identifier")
            .map(|n| get_node_text(&n, source).to_string())
    }

    /// Analyze the AST for TSS operations. When `allowed` is `Some(set)`,
    /// only keys whose name is in `set` are recorded (used for the
    /// file-scope pass so it stays limited to genuinely-global keys); when
    /// `None`, every key encountered under `node` is recorded (used for a
    /// single function's own scope).
    fn analyze_tss_operations(
        &self,
        node: &Node,
        source: &str,
        tss_keys: &mut HashMap<String, TssKeyInfo>,
        tss_set_calls: &mut HashSet<String>,
        tss_get_freed: &mut HashSet<String>,
        allowed: Option<&HashSet<String>>,
    ) {
        let is_allowed = |key_name: &str| allowed.is_none_or(|set| set.contains(key_name));

        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                // Check for tss_create
                if func_name == "tss_create" {
                    if let Some((key_name, has_destructor)) =
                        self.extract_tss_create_info(&call, source)
                    {
                        if is_allowed(&key_name) {
                            tss_keys.insert(
                                key_name.clone(),
                                TssKeyInfo {
                                    key_name,
                                    has_destructor,
                                    create_line: call.start_position().row + 1,
                                    create_column: call.start_position().column + 1,
                                },
                            );
                        }
                    }
                }

                // Check for tss_set
                if func_name == "tss_set" {
                    if let Some(key_name) = self.extract_tss_key_name(&call, source) {
                        if is_allowed(&key_name) {
                            tss_set_calls.insert(key_name);
                        }
                    }
                }

                // Check for free(tss_get(key))
                if func_name == "free" {
                    if let Some(key_name) = self.check_tss_get_in_free(&call, source) {
                        if is_allowed(&key_name) {
                            tss_get_freed.insert(key_name);
                        }
                    }
                }
            }
        }
    }

    /// Extract key name and destructor info from tss_create(&key, destructor)
    fn extract_tss_create_info(&self, call_node: &Node, source: &str) -> Option<(String, bool)> {
        if let Some(args) = call_node.child_by_field_name("arguments") {
            let arg_list = self.get_arguments(args, source);

            if arg_list.len() >= 2 {
                // First arg is &key
                let key_arg = arg_list[0].trim();
                let key_name = key_arg
                    .strip_prefix('&')
                    .map_or_else(|| key_arg.to_string(), |s| s.trim().to_string());

                // Second arg is destructor (NULL means no destructor)
                let destructor_arg = arg_list[1].trim();
                let has_destructor = destructor_arg != "NULL"
                    && destructor_arg != "0"
                    && destructor_arg != "nullptr"
                    && !destructor_arg.is_empty();

                return Some((key_name, has_destructor));
            }
        }
        None
    }

    /// Extract key name from tss_set(key, value) or tss_get(key)
    fn extract_tss_key_name(&self, call_node: &Node, source: &str) -> Option<String> {
        if let Some(args) = call_node.child_by_field_name("arguments") {
            let arg_list = self.get_arguments(args, source);

            if !arg_list.is_empty() {
                return Some(arg_list[0].trim().to_string());
            }
        }
        None
    }

    /// Check if free() is called on tss_get() result
    fn check_tss_get_in_free(&self, call_node: &Node, source: &str) -> Option<String> {
        if let Some(args) = call_node.child_by_field_name("arguments") {
            // Look for tss_get call inside free's arguments
            for i in 0..args.child_count() {
                if let Some(child) = args.child(i) {
                    if let Some(key) = self.find_tss_get_key(&child, source) {
                        return Some(key);
                    }
                }
            }
        }
        None
    }

    /// Find tss_get call and return the key name
    fn find_tss_get_key(&self, node: &Node, source: &str) -> Option<String> {
        let call = query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            n.child_by_field_name("function")
                .map(|f| get_node_text(&f, source) == "tss_get")
                .unwrap_or(false)
        })?;

        self.extract_tss_key_name(&call, source)
    }

    /// Get argument strings from an argument_list node
    fn get_arguments(&self, args_node: Node, source: &str) -> Vec<String> {
        let mut arguments = Vec::new();

        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                let kind = child.kind();
                if kind != "," && kind != "(" && kind != ")" {
                    let arg_text = get_node_text(&child, source).to_string();
                    arguments.push(arg_text);
                }
            }
        }

        arguments
    }
}
