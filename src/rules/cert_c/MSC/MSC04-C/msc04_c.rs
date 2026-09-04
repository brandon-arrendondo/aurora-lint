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
use std::collections::{HashMap, HashSet, VecDeque};
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

    /// Detect if `start` participates in a recursion cycle, returning the
    /// cycle path if one exists (e.g., ["a", "b", "a"] for mutual recursion).
    ///
    /// Breadth-first, not depth-first, and the choice is load-bearing twice
    /// over:
    ///
    /// * **The path has to be the same on every run.** Callee sets are
    ///   `HashSet`s, and Rust's default hasher is reseeded per process, so
    ///   any "report whichever cycle the traversal reached first" answer
    ///   varies between two runs of the same binary over the same tree.
    ///   That makes an unchanged finding look changed in a run-to-run diff.
    ///   Expanding each node's callees in sorted order and returning the
    ///   *shortest* cycle picks one path independently of hash order.
    ///
    /// * **A DFS here dropped real cycles.** The previous implementation
    ///   marked a node visited and never unmarked it on backtrack, so a node
    ///   first explored down one branch was closed to every later branch and
    ///   cycles routed through it were never found at all. A global visited
    ///   set is a reachability memo, not a cycle-search one. Under BFS that
    ///   is exactly what it means: the first time the search reaches a node
    ///   it has already reached it by a shortest path, so skipping it later
    ///   discards only longer paths, never the existence of a cycle.
    ///
    /// A self-loop on `start` alone is not reported here; direct recursion
    /// is detected and worded separately by the caller.
    fn find_cycle<'g>(
        &self,
        start: &'g str,
        graph: &'g HashMap<String, HashSet<String>>,
    ) -> Option<Vec<String>> {
        // `parent[n]` is the node BFS first reached `n` from, so the chain
        // back from any node spells a shortest path from `start`.
        let mut parent: HashMap<&'g str, &'g str> = HashMap::new();
        let mut visited: HashSet<&'g str> = HashSet::new();
        let mut queue: VecDeque<&'g str> = VecDeque::new();

        visited.insert(start);
        queue.push_back(start);

        while let Some(current) = queue.pop_front() {
            let Some(callees) = graph.get(current) else {
                continue;
            };
            let mut callees: Vec<&'g str> = callees.iter().map(String::as_str).collect();
            callees.sort_unstable();

            for callee in callees {
                if callee == start && current != start {
                    return Some(Self::reconstruct_cycle(start, current, &parent));
                }
                if visited.insert(callee) {
                    parent.insert(callee, current);
                    queue.push_back(callee);
                }
            }
        }

        None
    }

    /// Spell out `start -> .. -> tail -> start` by walking the BFS parent
    /// chain back from `tail`, where `tail` is the node found to call
    /// `start`.
    fn reconstruct_cycle(start: &str, tail: &str, parent: &HashMap<&str, &str>) -> Vec<String> {
        let mut reversed = vec![tail];
        let mut node = tail;
        while node != start {
            match parent.get(node) {
                Some(prev) => {
                    node = prev;
                    reversed.push(node);
                }
                None => break,
            }
        }
        reversed.reverse();

        let mut cycle: Vec<String> = reversed.into_iter().map(str::to_string).collect();
        cycle.push(start.to_string());
        cycle
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
