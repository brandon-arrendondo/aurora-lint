//! MEM01-C: Store a new value in pointers immediately after free()
//!
//! Uses CFG-based forward reachability to detect actual danger after free():
//! - Double-free: free(ptr) followed by free(ptr) on a reachable path
//! - Use-after-free: free(ptr) followed by ptr dereference/use on a reachable path
//!
//! Suppresses violations when the freed pointer is never used again (goes out of
//! scope, is reassigned, or function exits).

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::{self as cfg_mod, FunctionCfg};
use crate::analyze::dataflow::find_node_at_range;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use tree_sitter::Node;

pub struct Mem01C {
    function_cfgs: RefCell<HashMap<usize, FunctionCfg>>,
}

impl Mem01C {
    pub fn new() -> Self {
        Self {
            function_cfgs: RefCell::new(HashMap::new()),
        }
    }
}

#[derive(Debug, PartialEq)]
enum PtrAction {
    /// ptr = ... (any assignment to ptr, including NULL)
    Reassigned,
    /// free(ptr) called again
    FreedAgain,
    /// ptr used: dereferenced, indexed, passed to function, returned, etc.
    Used,
    /// Statement does not involve ptr
    Irrelevant,
}

impl CertRule for Mem01C {
    fn rule_id(&self) -> &'static str {
        "MEM01-C"
    }

    fn description(&self) -> &'static str {
        "Store a new value in pointers immediately after free()"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "MEM01-C"
    }

    fn set_function_cfgs(&self, cfgs: &HashMap<usize, FunctionCfg>) {
        *self.function_cfgs.borrow_mut() = cfgs.clone();
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Mem01C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() == "function_definition" {
            self.check_function(node, source, violations);
            return; // don't recurse into function — already handled
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_node(&child, source, violations);
            }
        }
    }

    fn check_function(&self, func_node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let body = match func_node.child_by_field_name("body") {
            Some(b) => b,
            None => return,
        };

        // Get pre-built CFG or build one on the fly
        let cfgs = self.function_cfgs.borrow();
        let inline_cfg;
        let cfg = if let Some(c) = cfgs.get(&func_node.start_byte()) {
            c
        } else if let Some(c) = cfg_mod::build_function_cfg(func_node, source) {
            inline_cfg = c;
            &inline_cfg
        } else {
            return; // no CFG available
        };

        // Find all free() calls in this function
        let free_calls = self.collect_free_calls(&body, source);

        for (ptr_name, free_byte, line, column) in free_calls {
            if self.ptr_has_post_free_use(cfg, &body, source, &ptr_name, free_byte) {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Pointer '{}' is used or freed again after free() without reassignment",
                        ptr_name
                    ),
                    file_path: String::new(),
                    line,
                    column,
                    suggestion: Some(format!(
                        "Set '{} = NULL;' after free({}) or remove the subsequent use",
                        ptr_name, ptr_name
                    )),
                    ..Default::default()
                });
            }
        }
    }

    /// Collect all free(ptr) call sites: (ptr_name, free_byte, line, column)
    fn collect_free_calls(&self, node: &Node, source: &str) -> Vec<(String, usize, usize, usize)> {
        let mut results = Vec::new();
        for node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func) = node.child_by_field_name("function") {
                let func_name = get_node_text(&func, source);
                if func_name == "free" {
                    if let Some(ptr_name) = self.extract_free_arg(&node, source) {
                        let pos = node.start_position();
                        results.push((ptr_name, node.start_byte(), pos.row + 1, pos.column + 1));
                    }
                }
            }
        }
        results
    }

    fn extract_free_arg(&self, call_node: &Node, source: &str) -> Option<String> {
        let args = call_node.child_by_field_name("arguments")?;
        for i in 0..args.child_count() {
            if let Some(arg) = args.child(i) {
                if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                    return Some(get_node_text(&arg, source).to_string());
                }
            }
        }
        None
    }

    /// BFS forward through the CFG from the free() call site.
    /// Returns true if ptr_name is used or freed again on any reachable path
    /// without an intervening reassignment.
    fn ptr_has_post_free_use(
        &self,
        cfg: &FunctionCfg,
        body: &Node,
        source: &str,
        ptr_name: &str,
        free_byte: usize,
    ) -> bool {
        let containing_block = match find_block_containing(cfg, free_byte) {
            Some(b) => b,
            None => return true, // conservative: can't locate block, flag it
        };

        // Scan remaining statements in the containing block after the free
        match self.scan_block_from(containing_block, body, source, ptr_name, free_byte) {
            Some(PtrAction::FreedAgain) | Some(PtrAction::Used) => return true,
            Some(PtrAction::Reassigned) => return false,
            _ => {} // fall through to BFS
        }

        // BFS through successor blocks
        let mut visited: HashSet<usize> = HashSet::new();
        visited.insert(containing_block.id);
        let mut queue: VecDeque<usize> = VecDeque::new();

        for (succ_id, _edge) in cfg.successors(containing_block.id) {
            queue.push_back(succ_id);
        }

        while let Some(block_id) = queue.pop_front() {
            if !visited.insert(block_id) {
                continue; // already visited
            }

            let block = match cfg.get_block(block_id) {
                Some(b) => b,
                None => continue,
            };

            // Scan all statements in this block from the start
            match self.scan_block_all(block, body, source, ptr_name) {
                Some(PtrAction::FreedAgain) | Some(PtrAction::Used) => return true,
                Some(PtrAction::Reassigned) => continue, // safe on this path
                _ => {
                    // No decisive action, continue to successors
                    for (succ_id, _edge) in cfg.successors(block_id) {
                        queue.push_back(succ_id);
                    }
                }
            }
        }

        false // all reachable paths are safe
    }

    /// Scan statements in a block starting AFTER after_byte.
    /// Returns the first decisive PtrAction found, or None.
    fn scan_block_from(
        &self,
        block: &crate::analyze::cfg::BasicBlock,
        body: &Node,
        source: &str,
        ptr_name: &str,
        after_byte: usize,
    ) -> Option<PtrAction> {
        for &(start, end) in &block.statements {
            if start <= after_byte {
                continue;
            }
            if let Some(stmt_node) = find_node_at_range(body, start, end) {
                let action = classify_stmt_for_ptr(&stmt_node, source, ptr_name);
                if action != PtrAction::Irrelevant {
                    return Some(action);
                }
            }
        }
        None
    }

    /// Scan all statements in a block from the beginning.
    fn scan_block_all(
        &self,
        block: &crate::analyze::cfg::BasicBlock,
        body: &Node,
        source: &str,
        ptr_name: &str,
    ) -> Option<PtrAction> {
        for &(start, end) in &block.statements {
            if let Some(stmt_node) = find_node_at_range(body, start, end) {
                let action = classify_stmt_for_ptr(&stmt_node, source, ptr_name);
                if action != PtrAction::Irrelevant {
                    return Some(action);
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Statement classification
// ---------------------------------------------------------------------------

/// Classify what a statement does to ptr_name.
fn classify_stmt_for_ptr(node: &Node, source: &str, ptr_name: &str) -> PtrAction {
    match node.kind() {
        "expression_statement" => {
            if let Some(expr) = node.child(0) {
                classify_expr_for_ptr(&expr, source, ptr_name)
            } else {
                PtrAction::Irrelevant
            }
        }
        "return_statement" => {
            // return ptr; is a use
            if node.child_count() > 1 {
                if let Some(expr) = node.child(1) {
                    if subtree_contains_identifier(&expr, source, ptr_name) {
                        return PtrAction::Used;
                    }
                }
            }
            PtrAction::Irrelevant
        }
        "declaration" => {
            // Check if ptr_name is the variable being declared (= reassignment)
            // vs used in the initializer of a different variable
            if let Some(declarator) = find_declarator_name(node, source) {
                if declarator == ptr_name {
                    return PtrAction::Reassigned;
                }
            }
            // Check if ptr_name appears in the initializer (e.g., int *q = ptr;)
            if subtree_contains_identifier(node, source, ptr_name) {
                return PtrAction::Used;
            }
            PtrAction::Irrelevant
        }
        // A while/for loop condition is stored as its header block's single
        // statement, wrapped in a parenthesized_expression (see cfg.rs
        // process_while/process_for). `while ((ptr = next()) != NULL)`
        // reassigns ptr *within* the condition before any use — the assignment
        // is nested inside a binary_expression, not a top-level
        // expression_statement, so it's invisible to classify_expr_for_ptr's
        // top-level match. Recognize it directly here (task 321).
        "parenthesized_expression" => {
            if subtree_assigns_identifier(node, source, ptr_name) {
                return PtrAction::Reassigned;
            }
            if subtree_contains_identifier(node, source, ptr_name) {
                PtrAction::Used
            } else {
                PtrAction::Irrelevant
            }
        }
        _ => {
            // For any other statement kind, check if ptr_name appears
            if subtree_contains_identifier(node, source, ptr_name) {
                PtrAction::Used
            } else {
                PtrAction::Irrelevant
            }
        }
    }
}

/// Classify an expression for ptr_name interaction.
fn classify_expr_for_ptr(expr: &Node, source: &str, ptr_name: &str) -> PtrAction {
    match expr.kind() {
        "assignment_expression" => {
            if let Some(left) = expr.child_by_field_name("left") {
                let left_text = get_node_text(&left, source);
                if left_text == ptr_name {
                    return PtrAction::Reassigned;
                }
            }
            // Check if ptr is used on the RHS or LHS (e.g., x = *ptr)
            if subtree_contains_identifier(expr, source, ptr_name) {
                return PtrAction::Used;
            }
            PtrAction::Irrelevant
        }
        "call_expression" => {
            if let Some(func) = expr.child_by_field_name("function") {
                let func_name = get_node_text(&func, source);
                if func_name == "free" {
                    if let Some(args) = expr.child_by_field_name("arguments") {
                        if arg_list_contains_identifier(&args, source, ptr_name) {
                            return PtrAction::FreedAgain;
                        }
                    }
                }
            }
            // Check if ptr is passed as argument to any function
            if let Some(args) = expr.child_by_field_name("arguments") {
                if arg_list_contains_identifier(&args, source, ptr_name) {
                    return PtrAction::Used;
                }
            }
            PtrAction::Irrelevant
        }
        "update_expression" => {
            // ptr++ or ptr--
            if subtree_contains_identifier(expr, source, ptr_name) {
                return PtrAction::Used;
            }
            PtrAction::Irrelevant
        }
        _ => {
            if subtree_contains_identifier(expr, source, ptr_name) {
                PtrAction::Used
            } else {
                PtrAction::Irrelevant
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check if an identifier matching ptr_name appears in the subtree.
/// Matches only identifier nodes (not substrings of other identifiers).
fn subtree_contains_identifier(node: &Node, source: &str, name: &str) -> bool {
    query::find_first_descendant(*node, |n| {
        n.kind() == "identifier" && get_node_text(&n, source) == name
    })
    .is_some()
}

/// True if an `assignment_expression` with `ptr_name` as its LHS appears
/// anywhere in the subtree (e.g. nested inside a condition's
/// parenthesized/binary wrapper: `(ptr = next()) != NULL`). See the
/// `parenthesized_expression` case of `classify_stmt_for_ptr` (task 321).
fn subtree_assigns_identifier(node: &Node, source: &str, name: &str) -> bool {
    query::find_first_descendant(*node, |n| {
        if n.kind() != "assignment_expression" {
            return false;
        }
        n.child_by_field_name("left")
            .map(|left| get_node_text(&left, source) == name)
            .unwrap_or(false)
    })
    .is_some()
}

/// Check if ptr_name appears as an argument in an argument_list.
fn arg_list_contains_identifier(args: &Node, source: &str, name: &str) -> bool {
    for i in 0..args.child_count() {
        if let Some(arg) = args.child(i) {
            if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                if subtree_contains_identifier(&arg, source, name) {
                    return true;
                }
            }
        }
    }
    false
}

/// Extract the declared variable name from a declaration node.
/// Handles: `int x`, `char *p`, `int *p = malloc(...)`, etc.
fn find_declarator_name(decl: &Node, source: &str) -> Option<String> {
    for i in 0..decl.child_count() {
        if let Some(child) = decl.child(i) {
            match child.kind() {
                "init_declarator" => {
                    // init_declarator has declarator as first field
                    if let Some(d) = child.child_by_field_name("declarator") {
                        return extract_identifier_from_declarator(&d, source);
                    }
                }
                "pointer_declarator" | "array_declarator" | "identifier" => {
                    return extract_identifier_from_declarator(&child, source);
                }
                _ => {}
            }
        }
    }
    None
}

/// Drill into nested declarators (pointer_declarator, array_declarator) to find the identifier.
fn extract_identifier_from_declarator(node: &Node, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" => Some(get_node_text(node, source).to_string()),
        "pointer_declarator" | "array_declarator" => {
            if let Some(d) = node.child_by_field_name("declarator") {
                extract_identifier_from_declarator(&d, source)
            } else {
                // Walk children looking for identifier
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if let Some(name) = extract_identifier_from_declarator(&child, source) {
                            return Some(name);
                        }
                    }
                }
                None
            }
        }
        _ => None,
    }
}

/// Find the basic block containing the given byte offset.
fn find_block_containing(
    cfg: &FunctionCfg,
    byte_offset: usize,
) -> Option<&crate::analyze::cfg::BasicBlock> {
    // First try statement-level containment (more precise)
    for block in &cfg.blocks {
        for &(start, end) in &block.statements {
            if byte_offset >= start && byte_offset < end {
                return Some(block);
            }
        }
    }
    // Fallback to block byte range
    cfg.blocks.iter().find(|block| {
        block.byte_range.0 > 0
            && byte_offset >= block.byte_range.0
            && byte_offset < block.byte_range.1
    })
}
