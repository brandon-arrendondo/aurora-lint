//! MSC04-C: Do not use recursive function calls
//!
//! Detects functions that participate in recursion cycles:
//! 1. Direct recursion: function calls itself
//! 2. Indirect recursion: function A calls B, B calls A (or longer cycles)
//!
//! Maps to BRULE-058 (Constrained tier): prohibits recursion.
//! Direct recursion is detected from AST alone; indirect recursion requires
//! prescan data (-d flag) for cross-function call graph analysis.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

#[derive(Debug)]
pub struct Msc04C {
    call_graph: RefCell<HashMap<String, HashSet<String>>>,
    ambiguous_call_targets: RefCell<HashSet<String>>,
}

impl Msc04C {
    pub fn new() -> Self {
        Msc04C {
            call_graph: RefCell::new(HashMap::new()),
            ambiguous_call_targets: RefCell::new(HashSet::new()),
        }
    }

    /// Drop edges to a callee that can only be resolved to a same-named
    /// function by coincidental name matching -- a call through a struct
    /// field or a parameter-shadowed identifier (see
    /// `ProjectContext::ambiguous_call_targets`). Such a callee is opaque
    /// dispatch: it may or may not actually reach back into the caller, and
    /// chasing it through the cycle-detection DFS fabricates recursion
    /// cycles that don't exist in the source (task 562).
    fn strip_ambiguous_callees(
        graph: &HashMap<String, HashSet<String>>,
        ambiguous: &HashSet<String>,
    ) -> HashMap<String, HashSet<String>> {
        if ambiguous.is_empty() {
            return graph.clone();
        }
        graph
            .iter()
            .map(|(caller, callees)| {
                let filtered: HashSet<String> = callees
                    .iter()
                    .filter(|callee| !ambiguous.contains(callee.as_str()))
                    .cloned()
                    .collect();
                (caller.clone(), filtered)
            })
            .collect()
    }

    /// Extract function name from a function_definition node.
    fn extract_func_name<'a>(&self, node: &Node<'a>, source: &'a str) -> Option<String> {
        let declarator = node.child_by_field_name("declarator")?;
        self.find_identifier_in_declarator(&declarator, source)
    }

    fn find_identifier_in_declarator(&self, node: &Node, source: &str) -> Option<String> {
        match node.kind() {
            "identifier" => {
                let name = get_node_text(node, source);
                if name.is_empty() {
                    None
                } else {
                    Some(name.to_string())
                }
            }
            "function_declarator" | "pointer_declarator" | "parenthesized_declarator" => {
                // Recurse into the declarator child
                let inner = node.child_by_field_name("declarator")?;
                self.find_identifier_in_declarator(&inner, source)
            }
            _ => None,
        }
    }

    /// Collect all direct function calls in a subtree (identifiers in call_expression).
    fn collect_callees(&self, node: &Node, source: &str, callees: &mut HashSet<String>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                if function.kind() == "identifier" {
                    let name = get_node_text(&function, source);
                    if !name.is_empty() {
                        callees.insert(name.to_string());
                    }
                }
            }
        }
    }

    /// Detect if `start` participates in a recursion cycle via DFS on the call graph.
    /// Returns the cycle path if found (e.g., ["a", "b", "a"] for mutual recursion).
    fn find_cycle(
        &self,
        start: &str,
        graph: &HashMap<String, HashSet<String>>,
    ) -> Option<Vec<String>> {
        let mut visited = HashSet::new();
        let mut path = Vec::new();
        self.dfs_cycle(start, start, graph, &mut visited, &mut path)
    }

    fn dfs_cycle(
        &self,
        current: &str,
        target: &str,
        graph: &HashMap<String, HashSet<String>>,
        visited: &mut HashSet<String>,
        path: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        visited.insert(current.to_string());
        path.push(current.to_string());

        if let Some(callees) = graph.get(current) {
            for callee in callees {
                if callee == target && path.len() > 1 {
                    // Found cycle back to start
                    let mut cycle = path.clone();
                    cycle.push(target.to_string());
                    return Some(cycle);
                }
                if !visited.contains(callee.as_str()) {
                    if let Some(cycle) = self.dfs_cycle(callee, target, graph, visited, path) {
                        return Some(cycle);
                    }
                }
            }
        }

        path.pop();
        None // no cycle through this path
    }

    /// Check if a recursive function has a bounded base case: at least one
    /// parameter, and a conditional return in the body whose condition
    /// references a parameter. This indicates the recursion is controlled.
    fn has_bounded_base_case(&self, func_node: &Node, source: &str) -> bool {
        // Collect parameter names
        let params = self.collect_param_names(func_node, source);
        if params.is_empty() {
            return false; // No params → can't have parameter-dependent base case
        }

        let body = match func_node.child_by_field_name("body") {
            Some(b) => b,
            None => return false,
        };

        // Look for if_statement children whose condition references a param
        // and whose consequence contains a return_statement
        self.find_param_guarded_return(&body, source, &params)
    }

    /// Collect parameter names from a function_definition.
    fn collect_param_names(&self, func_node: &Node, source: &str) -> HashSet<String> {
        let mut params = HashSet::new();
        let declarator = match func_node.child_by_field_name("declarator") {
            Some(d) => d,
            None => return params,
        };
        // function_declarator → parameters (parameter_list)
        for param in query::find_descendants_of_kind(declarator, "parameter_declaration") {
            // The declarator child holds the parameter name
            if let Some(decl) = param.child_by_field_name("declarator") {
                if let Some(name) = self.find_identifier_in_declarator(&decl, source) {
                    params.insert(name);
                }
            }
        }
        params
    }

    /// Search for an if_statement whose condition references a parameter and
    /// whose body contains a return_statement.
    fn find_param_guarded_return(
        &self,
        node: &Node,
        source: &str,
        params: &HashSet<String>,
    ) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "if_statement" {
                return false;
            }
            let Some(cond) = n.child_by_field_name("condition") else {
                return false;
            };
            if !self.references_any_param(&cond, source, params) {
                return false;
            }
            // Check consequence for return
            let Some(consequence) = n.child_by_field_name("consequence") else {
                return false;
            };
            self.contains_return(&consequence)
        })
        .is_some()
    }

    /// Check if a node or its descendants reference any of the given parameter names.
    fn references_any_param(&self, node: &Node, source: &str, params: &HashSet<String>) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "identifier" {
                return false;
            }
            let name = get_node_text(&n, source);
            params.contains(name.trim())
        })
        .is_some()
    }

    /// Check if a node or its descendants contain a return_statement.
    fn contains_return(&self, node: &Node) -> bool {
        query::find_first_descendant(*node, |n| n.kind() == "return_statement").is_some()
    }

    fn check_function(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let func_name = match self.extract_func_name(node, source) {
            Some(n) => n,
            None => return,
        };

        // Collect callees within this function body
        let mut callees = HashSet::new();
        if let Some(body) = node.child_by_field_name("body") {
            self.collect_callees(&body, source, &mut callees);
        }

        // 1. Direct recursion: function calls itself
        if callees.contains(&func_name) {
            // Suppress if the function has a bounded base case:
            // a parameter-dependent conditional return before the self-call.
            // This indicates controlled recursion (CWE-674 compliant).
            if self.has_bounded_base_case(node, source) {
                return;
            }
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                message: format!(
                    "Function '{}' calls itself directly (direct recursion)",
                    func_name
                ),
                file_path: String::new(),
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                suggestion: Some("Refactor to use iteration instead of recursion".to_string()),
                requires_manual_review: None,
            });
            return; // Don't also report indirect cycle
        }

        // 2. Indirect recursion: check call graph for cycles through this function
        let graph = self.call_graph.borrow();
        if graph.is_empty() {
            return; // No prescan data — can only detect direct recursion
        }

        // Build a local graph that includes this function's callees
        // (prescan graph may not include the current file if it wasn't prescanned).
        // Strip ambiguous (struct-field / parameter-shadowed) callees here too --
        // `callees` was collected fresh from this function's own body and hasn't
        // gone through `strip_ambiguous_callees` yet (see task 562).
        let ambiguous = self.ambiguous_call_targets.borrow();
        let callees: HashSet<String> = callees
            .into_iter()
            .filter(|c| !ambiguous.contains(c))
            .collect();
        let mut local_graph = graph.clone();
        local_graph.insert(func_name.clone(), callees);

        if let Some(cycle) = self.find_cycle(&func_name, &local_graph) {
            let cycle_str = cycle.join(" -> ");
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                message: format!(
                    "Function '{}' participates in indirect recursion: {}",
                    func_name, cycle_str
                ),
                file_path: String::new(),
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                suggestion: Some("Refactor to eliminate the recursion cycle".to_string()),
                requires_manual_review: None,
            });
        }
    }

    fn walk_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function(&func, source, violations);
        }
    }
}

impl CertRule for Msc04C {
    fn rule_id(&self) -> &'static str {
        "MSC04-C"
    }

    fn description(&self) -> &'static str {
        "Do not use recursive function calls"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "MSC04-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.call_graph.borrow_mut() =
            Self::strip_ambiguous_callees(&context.call_graph, &context.ambiguous_call_targets);
        *self.ambiguous_call_targets.borrow_mut() = context.ambiguous_call_targets.clone();
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.walk_node(node, source, violations);
    }
}
