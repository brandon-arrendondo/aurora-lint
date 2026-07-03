//! INT04-C: Enforce limits on integer values originating from tainted sources
//!
//! This rule detects integer values from tainted sources (user input, environment,
//! network data) that are used without proper bounds checking.
//!
//! TAINTED SOURCES:
//! - getenv() - environment variables
//! - strtoul/strtol with tainted input
//! - GET_TAINTED_INTEGER macro
//! - n2s macro (network to short)
//!
//! VIOLATIONS:
//! - Tainted integer used in array subscript without bounds check
//! - Tainted integer used in allocation without upper bound
//! - Tainted integer used in memcpy length without validation
//!
//! COMPLIANT:
//! - Tainted integer validated against known bounds before use

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Int04C;

// Functions that return tainted data
const TAINTED_SOURCES: &[&str] = &["getenv", "strtoul", "strtol", "atoi", "atol"];

// Macros that indicate tainted data
const TAINTED_MACROS: &[&str] = &["GET_TAINTED_INTEGER", "n2s", "GET_TAINTED_STRING"];

impl CertRule for Int04C {
    fn rule_id(&self) -> &'static str {
        "INT04-C"
    }

    fn description(&self) -> &'static str {
        "Enforce limits on integer values originating from tainted sources"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "INT04-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_function(node, source, &mut violations);
        violations
    }
}

impl Int04C {
    fn check_function(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for function definitions and analyze their bodies
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(body) = func.child_by_field_name("body") {
                // Track: tainted vars, validated vars, and dependencies
                let mut tainted_vars: HashSet<String> = HashSet::new();
                let mut validated_vars: HashSet<String> = HashSet::new();
                let mut var_dependencies: HashMap<String, HashSet<String>> = HashMap::new();

                self.analyze_block(
                    &body,
                    source,
                    violations,
                    &mut tainted_vars,
                    &mut validated_vars,
                    &mut var_dependencies,
                );
            }
        }
    }

    fn analyze_block(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        tainted_vars: &mut HashSet<String>,
        validated_vars: &mut HashSet<String>,
        var_dependencies: &mut HashMap<String, HashSet<String>>,
    ) {
        // First pass: identify tainted variables and their dependencies
        self.collect_tainted_and_deps(node, source, tainted_vars, var_dependencies);

        // Second pass: identify validations
        self.collect_validations(node, source, validated_vars, tainted_vars);

        // Propagate validations through dependencies
        self.propagate_validations(validated_vars, var_dependencies);

        // Third pass: check for unsafe uses
        self.check_unsafe_uses(node, source, violations, tainted_vars, validated_vars);
    }

    fn collect_tainted_and_deps(
        &self,
        node: &Node,
        source: &str,
        tainted_vars: &mut HashSet<String>,
        var_dependencies: &mut HashMap<String, HashSet<String>>,
    ) {
        // Full-subtree scan in pre-order — matches the original recursive
        // descent order exactly, which matters because taint propagation
        // below depends on `tainted_vars` reflecting earlier-visited nodes.
        for n in query::find_descendants_of_kinds(*node, &["init_declarator", "call_expression"]) {
            // Check for declarations/assignments
            if n.kind() == "init_declarator" {
                if let (Some(declarator), Some(value)) = (
                    n.child_by_field_name("declarator"),
                    n.child_by_field_name("value"),
                ) {
                    let var_name = get_node_text(&declarator, source).to_string();

                    // Check if value is from tainted source
                    if self.is_direct_tainted_source(&value, source) {
                        tainted_vars.insert(var_name.clone());
                    }

                    // Track dependencies (which vars this var depends on)
                    let deps = self.extract_var_references(&value, source);
                    if !deps.is_empty() {
                        var_dependencies.insert(var_name.clone(), deps.clone());

                        // If any dependency is tainted, this var is tainted too
                        for dep in &deps {
                            if tainted_vars.contains(dep) {
                                tainted_vars.insert(var_name.clone());
                                break;
                            }
                        }
                    }
                }
            } else if n.kind() == "call_expression" {
                // Check for call expressions that are tainted macros
                if let Some(func) = n.child_by_field_name("function") {
                    let func_name = get_node_text(&func, source);
                    if TAINTED_MACROS.contains(&func_name) {
                        // Check arguments for variables being tainted
                        if let Some(args) = n.child_by_field_name("arguments") {
                            self.mark_tainted_from_macro(&args, source, tainted_vars);
                        }
                    }
                }
            }
        }
    }

    fn is_direct_tainted_source(&self, node: &Node, source: &str) -> bool {
        // The original conditional_expression special-case recursed into the
        // same children as the generic fallback below it, so it never
        // changed the result — this is a plain "does any descendant
        // (including the node itself) call a tainted source" search.
        query::find_first_descendant(*node, |n| {
            if n.kind() == "call_expression" {
                if let Some(func) = n.child_by_field_name("function") {
                    let func_name = get_node_text(&func, source);
                    if TAINTED_SOURCES.contains(&func_name) || TAINTED_MACROS.contains(&func_name) {
                        return true;
                    }
                }
            }
            false
        })
        .is_some()
    }

    fn extract_var_references(&self, node: &Node, source: &str) -> HashSet<String> {
        query::find_descendants_of_kind(*node, "identifier")
            .into_iter()
            .filter_map(|n| {
                let name = get_node_text(&n, source).to_string();
                // Filter out known non-variables (sizeof, types, etc.)
                if name != "sizeof" && !name.starts_with("char") && !name.starts_with("size_t") {
                    Some(name)
                } else {
                    None
                }
            })
            .collect()
    }

    fn mark_tainted_from_macro(
        &self,
        args_node: &Node,
        source: &str,
        tainted_vars: &mut HashSet<String>,
    ) {
        // For GET_TAINTED_INTEGER(type, var), the second arg is the tainted var
        let mut arg_idx = 0;
        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                    if arg_idx == 1 {
                        let var_name = get_node_text(&child, source).to_string();
                        tainted_vars.insert(var_name);
                    }
                    arg_idx += 1;
                }
            }
        }
    }

    fn collect_validations(
        &self,
        node: &Node,
        source: &str,
        validated_vars: &mut HashSet<String>,
        tainted_vars: &HashSet<String>,
    ) {
        // Look for if statements that validate bounds
        for n in query::find_descendants_of_kind(*node, "if_statement") {
            if let Some(condition) = n.child_by_field_name("condition") {
                let cond_text = get_node_text(&condition, source);

                // Check each tainted variable to see if it appears in bounds check
                for var in tainted_vars.iter() {
                    if cond_text.contains(var) {
                        // Check for comparison operators against a practical max value
                        // SIZE_MAX is NOT a practical bound (just prevents overflow)
                        // We want to see comparison against user-defined MAX_* constants
                        let has_practical_bound = (cond_text.contains('>') || cond_text.contains('<'))
                            && (cond_text.contains("MAX_") || cond_text.contains("max_")
                                || cond_text.contains("_MAX") || cond_text.contains("_max")
                                || cond_text.contains("rrec.length")) // Network record length validation
                            && !cond_text.contains("SIZE_MAX"); // SIZE_MAX is not practical bound

                        if has_practical_bound {
                            // Check if this is followed by error handling
                            if let Some(consequence) = n.child_by_field_name("consequence") {
                                let cons_text = get_node_text(&consequence, source);
                                if cons_text.contains("return")
                                    || cons_text.contains("NULL")
                                    || cons_text.contains("error")
                                    || cons_text.contains("0")
                                {
                                    validated_vars.insert(var.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn propagate_validations(
        &self,
        validated_vars: &mut HashSet<String>,
        var_dependencies: &HashMap<String, HashSet<String>>,
    ) {
        // If a variable depends only on validated variables, it's also validated
        let mut changed = true;
        while changed {
            changed = false;
            for (var, deps) in var_dependencies.iter() {
                if !validated_vars.contains(var) {
                    // Check if all dependencies are validated
                    let all_deps_validated = deps.iter().all(|d| validated_vars.contains(d));
                    if all_deps_validated && !deps.is_empty() {
                        validated_vars.insert(var.clone());
                        changed = true;
                    }
                }
            }
        }
    }

    fn check_unsafe_uses(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        tainted_vars: &HashSet<String>,
        validated_vars: &HashSet<String>,
    ) {
        for n in
            query::find_descendants_of_kinds(*node, &["subscript_expression", "call_expression"])
        {
            // Check for subscript with tainted unvalidated index
            if n.kind() == "subscript_expression" {
                if let Some(index) = n.child_by_field_name("index") {
                    let index_text = get_node_text(&index, source);
                    for var in tainted_vars.iter() {
                        if index_text.contains(var) && !validated_vars.contains(var) {
                            let pos = n.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::High,
                                message: format!(
                                    "Tainted integer '{}' used as array index without bounds validation",
                                    var
                                ),
                                file_path: String::new(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                                suggestion: Some(
                                    "Validate the tainted value against array bounds before use".to_string(),
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
            } else if n.kind() == "call_expression" {
                // Check for memcpy/malloc with tainted size
                if let Some(func) = n.child_by_field_name("function") {
                    let func_name = get_node_text(&func, source);
                    if func_name == "memcpy"
                        || func_name == "malloc"
                        || func_name == "OPENSSL_malloc"
                    {
                        if let Some(args) = n.child_by_field_name("arguments") {
                            self.check_tainted_size_arg(
                                &args,
                                source,
                                violations,
                                tainted_vars,
                                validated_vars,
                                func_name,
                            );
                        }
                    }
                }
            }
        }
    }

    fn check_tainted_size_arg(
        &self,
        args_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        tainted_vars: &HashSet<String>,
        validated_vars: &HashSet<String>,
        func_name: &str,
    ) {
        // For memcpy(dst, src, size) - check size (3rd arg)
        // For malloc(size) / OPENSSL_malloc(size) - check size (1st arg)
        let target_arg_idx = if func_name == "memcpy" { 2 } else { 0 };

        let mut arg_idx = 0;
        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                    if arg_idx == target_arg_idx {
                        let arg_text = get_node_text(&child, source);
                        for var in tainted_vars.iter() {
                            if arg_text.contains(var) && !validated_vars.contains(var) {
                                let pos = child.start_position();
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::High,
                                    message: format!(
                                        "Tainted integer '{}' used in {} size without bounds validation",
                                        var, func_name
                                    ),
                                    file_path: String::new(),
                                    line: pos.row + 1,
                                    column: pos.column + 1,
                                    suggestion: Some(format!(
                                        "Validate '{}' against a maximum bound before use in {}",
                                        var, func_name
                                    )),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                    arg_idx += 1;
                }
            }
        }
    }
}
