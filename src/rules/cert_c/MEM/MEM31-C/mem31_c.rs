use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::analyze::function_summary::FunctionSummary;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Mem31C {
    function_summaries: RefCell<HashMap<String, FunctionSummary>>,
}

impl Mem31C {
    pub fn new() -> Self {
        Self {
            function_summaries: RefCell::new(HashMap::new()),
        }
    }
}

impl CertRule for Mem31C {
    fn rule_id(&self) -> &'static str {
        "MEM31-C"
    }

    fn description(&self) -> &'static str {
        "Free dynamically allocated memory when no longer needed"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "MEM31-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let summaries = self.function_summaries.borrow();

        // Analyze each function independently for memory leaks
        if node.kind() == "function_definition" {
            let mut analyzer = MemoryLeakAnalyzer::new(&summaries);
            analyzer.analyze_function(node, source, &mut violations);
        }

        // Recursively check child nodes
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                violations.extend(self.check(&child, source));
            }
        }

        violations
    }
}

struct MemoryLeakAnalyzer<'a> {
    // Track allocated memory by variable name
    allocated_memory: HashMap<String, AllocInfo>,
    // Track freed memory: var_name -> (line, column) of free call
    freed_memory: HashMap<String, (usize, usize)>,
    // Track variables that are returned or stored globally
    escaped_memory: HashSet<String>,
    // Track variables known to be NULL in current scope (from NULL checks)
    null_variables: HashSet<String>,
    // Collect double-free violations during analysis
    double_free_violations: Vec<RuleViolation>,
    // Collect leak violations found at early returns
    leak_violations: Vec<RuleViolation>,
    // Track if we're inside a loop (for double-free detection)
    in_loop: bool,
    // Track loop nesting depth for proper double-free detection
    loop_depth: usize,
    // Track what variables are freed at each label (for goto analysis)
    label_frees: HashMap<String, HashSet<String>>,
    // Track realloc relationships: result_var -> old_ptr
    realloc_relations: HashMap<String, String>,
    // Track if signal() has been called in this function
    signal_registered: bool,
    // Track loop allocation/free patterns: array_base -> (alloc_condition, free_condition)
    loop_array_patterns: HashMap<String, (Option<String>, Option<String>)>,
    // Function summaries from prescan for inter-procedural analysis
    function_summaries: &'a HashMap<String, FunctionSummary>,
}

#[derive(Debug, Clone)]
struct AllocInfo {
    line: usize,
    column: usize,
    alloc_type: String,
}

impl<'a> MemoryLeakAnalyzer<'a> {
    fn new(function_summaries: &'a HashMap<String, FunctionSummary>) -> Self {
        Self {
            allocated_memory: HashMap::new(),
            freed_memory: HashMap::new(),
            escaped_memory: HashSet::new(),
            null_variables: HashSet::new(),
            double_free_violations: Vec::new(),
            leak_violations: Vec::new(),
            in_loop: false,
            loop_depth: 0,
            label_frees: HashMap::new(),
            realloc_relations: HashMap::new(),
            signal_registered: false,
            loop_array_patterns: HashMap::new(),
            function_summaries,
        }
    }

    fn analyze_function(
        &mut self,
        func_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(body) = func_node.child_by_field_name("body") {
            // Pre-analysis: collect what variables are freed at each label
            self.collect_label_frees(&body, source);

            // Main pass: collect all memory operations and detect double-frees
            self.analyze_node(&body, source);

            // Add double-free violations found during analysis
            violations.append(&mut self.double_free_violations);

            // Add leak violations found at early returns
            violations.append(&mut self.leak_violations);

            // Final pass: check for leaks at end of function
            self.detect_leaks(violations);
        }
    }

    /// Find array allocation or free pattern in a for loop
    /// Returns (array_base, is_subscript) if found
    fn find_loop_array_pattern(
        &self,
        node: &Node,
        source: &str,
        is_alloc: bool,
    ) -> Option<(String, bool)> {
        self.find_loop_array_pattern_recursive(node, source, is_alloc)
    }

    fn find_loop_array_pattern_recursive(
        &self,
        node: &Node,
        source: &str,
        is_alloc: bool,
    ) -> Option<(String, bool)> {
        if is_alloc {
            // Looking for array[i] = malloc() pattern
            if node.kind() == "assignment_expression" {
                if let Some(left) = node.child_by_field_name("left") {
                    if left.kind() == "subscript_expression" {
                        if let Some(right) = node.child_by_field_name("right") {
                            if self.is_allocation_call(&right, source) {
                                // Extract array base (e.g., "array" from "array[i]")
                                if let Some(base) = left.child_by_field_name("argument") {
                                    let base_name = ast_utils::get_node_text_owned(&base, source);
                                    return Some((base_name, true));
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // Looking for free(array[i]) pattern
            if node.kind() == "call_expression" {
                if let Some(function) = node.child_by_field_name("function") {
                    let func_name = ast_utils::get_node_text_owned(&function, source);
                    if func_name == "free" {
                        if let Some(arguments) = node.child_by_field_name("arguments") {
                            for i in 0..arguments.child_count() {
                                if let Some(arg) = arguments.child(i) {
                                    if arg.kind() == "subscript_expression" {
                                        if let Some(base) = arg.child_by_field_name("argument") {
                                            let base_name =
                                                ast_utils::get_node_text_owned(&base, source);
                                            return Some((base_name, true));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Recurse
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(result) =
                    self.find_loop_array_pattern_recursive(&child, source, is_alloc)
                {
                    return Some(result);
                }
            }
        }
        None
    }

    /// Check for macro calls that might hide early returns (e.g., CHECK_AND_RETURN, ASSERT_RETURN)
    fn check_for_return_macro(&mut self, node: &Node, source: &str) {
        // Find call_expression children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "call_expression" {
                    if let Some(function) = child.child_by_field_name("function") {
                        let func_name = ast_utils::get_node_text_owned(&function, source);
                        let upper_name = func_name.to_uppercase();

                        // Heuristic: macro names containing RETURN, EXIT, or similar might hide early returns
                        if upper_name.contains("RETURN")
                            || upper_name.contains("EXIT")
                            || upper_name.contains("ABORT")
                        {
                            // Check if there's allocated memory that would be leaked
                            let call_pos = child.start_position();
                            for (var_name, alloc_info) in &self.allocated_memory {
                                if self.escaped_memory.contains(var_name)
                                    || self.freed_memory.contains_key(var_name)
                                    || self.null_variables.contains(var_name)
                                    || var_name.contains('@')
                                {
                                    continue;
                                }

                                self.leak_violations.push(RuleViolation {
                                    rule_id: "MEM31-C".to_string(),
                                    severity: Severity::High,
                                    message: format!(
                                        "Potential memory leak: '{}' allocated with '{}' may not be freed if {} causes early return",
                                        var_name, alloc_info.alloc_type, func_name
                                    ),
                                    file_path: String::new(),
                                    line: call_pos.row + 1,
                                    column: call_pos.column + 1,
                                    suggestion: Some(format!(
                                        "Free '{}' before {} or restructure to avoid potential leak",
                                        var_name, func_name
                                    )),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Pre-analyze function to find what variables are freed at each labeled statement
    fn collect_label_frees(&mut self, node: &Node, source: &str) {
        if node.kind() == "labeled_statement" {
            // Get the label name
            if let Some(label_node) = node.child(0) {
                if label_node.kind() == "statement_identifier" {
                    let label_name = ast_utils::get_node_text_owned(&label_node, source);
                    // Collect all free() calls reachable from this label
                    let mut freed_vars = HashSet::new();
                    self.collect_frees_in_label(node, source, &mut freed_vars);
                    self.label_frees.insert(label_name, freed_vars);
                }
            }
        }

        // Recurse to find all labels
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_label_frees(&child, source);
            }
        }
    }

    /// Collect all free() calls reachable from a labeled statement
    fn collect_frees_in_label(&self, node: &Node, source: &str, freed_vars: &mut HashSet<String>) {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = ast_utils::get_node_text_owned(&function, source);
                if func_name == "free" {
                    if let Some(arguments) = node.child_by_field_name("arguments") {
                        for i in 0..arguments.child_count() {
                            if let Some(arg) = arguments.child(i) {
                                if matches!(
                                    arg.kind(),
                                    "identifier" | "field_expression" | "subscript_expression"
                                ) {
                                    let var_name = ast_utils::get_node_text_owned(&arg, source);
                                    freed_vars.insert(var_name);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Recurse, but stop at return statements (code after return is unreachable)
        if node.kind() == "return_statement" {
            return;
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_frees_in_label(&child, source, freed_vars);
            }
        }
    }

    fn analyze_node(&mut self, node: &Node, source: &str) {
        match node.kind() {
            "declaration" | "expression_statement" => {
                // Check for macro calls that might hide early returns
                self.check_for_return_macro(node, source);
                self.process_statement(node, source);
            }
            "assignment_expression" => {
                self.process_assignment(node, source);
            }
            "call_expression" => {
                self.process_call(node, source);
            }
            "return_statement" => {
                self.process_return(node, source);
            }
            "goto_statement" => {
                // Goto can bypass cleanup code - check for potential leaks
                // First, find the target label
                let mut target_label = String::new();
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "statement_identifier" {
                            target_label = ast_utils::get_node_text_owned(&child, source);
                            break;
                        }
                    }
                }

                // Get what variables are freed at the target label
                let label_freed_vars = self.label_frees.get(&target_label).cloned();

                let goto_pos = node.start_position();
                for (var_name, alloc_info) in &self.allocated_memory {
                    if self.escaped_memory.contains(var_name)
                        || self.freed_memory.contains_key(var_name)
                        || self.null_variables.contains(var_name)
                        || var_name.contains('@')
                    {
                        continue;
                    }

                    // Check if this variable is freed at the target label
                    // Also check for field expression variants (e.g., bundle->data matches bundle)
                    let is_freed_at_label = label_freed_vars.as_ref().is_some_and(|freed| {
                        freed.contains(var_name)
                            || freed
                                .iter()
                                .any(|f| f.starts_with(&format!("{}->", var_name)))
                            || freed.iter().any(|f| {
                                // Check if var_name is a field and its container is freed
                                if let Some(base) = var_name.split("->").next() {
                                    f == base
                                } else {
                                    false
                                }
                            })
                    });

                    if is_freed_at_label {
                        continue; // This variable is properly cleaned up at the label
                    }

                    self.leak_violations.push(RuleViolation {
                        rule_id: "MEM31-C".to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Potential memory leak: '{}' allocated with '{}' may not be freed due to goto",
                            var_name, alloc_info.alloc_type
                        ),
                        file_path: String::new(),
                        line: goto_pos.row + 1,
                        column: goto_pos.column + 1,
                        suggestion: Some(format!(
                            "Ensure '{}' is freed before this goto or at the target label",
                            var_name
                        )),
                        ..Default::default()
                    });
                }
            }
            "for_statement" => {
                // Track loop condition for array allocation/free mismatch detection
                let loop_condition = node
                    .child_by_field_name("condition")
                    .map(|c| ast_utils::get_node_text_owned(&c, source));

                self.in_loop = true;
                self.loop_depth += 1;

                // Pre-scan for allocation and free patterns in this loop
                let alloc_info = self.find_loop_array_pattern(node, source, true);
                let free_info = self.find_loop_array_pattern(node, source, false);

                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        self.analyze_node(&child, source);
                    }
                }

                // Record pattern for later comparison
                if let Some((array_base, _)) = alloc_info {
                    if let Some(cond) = &loop_condition {
                        let entry = self
                            .loop_array_patterns
                            .entry(array_base)
                            .or_insert((None, None));
                        entry.0 = Some(cond.clone());
                    }
                }
                if let Some((array_base, _)) = free_info {
                    if let Some(cond) = &loop_condition {
                        let entry = self
                            .loop_array_patterns
                            .entry(array_base)
                            .or_insert((None, None));
                        entry.1 = Some(cond.clone());
                    }
                }

                self.loop_depth -= 1;
                if self.loop_depth == 0 {
                    self.in_loop = false;
                }
            }
            "while_statement" | "do_statement" => {
                // Track loop nesting for double-free detection
                self.in_loop = true;
                self.loop_depth += 1;
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        self.analyze_node(&child, source);
                    }
                }
                self.loop_depth -= 1;
                if self.loop_depth == 0 {
                    self.in_loop = false;
                }
            }
            "if_statement" => {
                // For if statements, use branch-aware analysis
                let saved_freed = self.freed_memory.clone();
                let saved_null = self.null_variables.clone();
                let saved_allocated = self.allocated_memory.clone();

                // Check if condition is a NULL check (var == NULL)
                let null_check_var = self.get_null_check_variable(node, source);

                // Check if condition is a non-NULL check (var != NULL)
                let non_null_check_var = self.get_non_null_check_variable(node, source);

                // Check if condition is a truthiness check (if (ptr))
                let truthiness_var = self.get_truthiness_check_variable(node, source);

                // Find true branch (compound_statement) and else clause
                let mut true_branch: Option<Node> = None;
                let mut else_clause: Option<Node> = None;

                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "compound_statement" && true_branch.is_none() {
                            true_branch = Some(child);
                        } else if child.kind() == "else_clause" {
                            else_clause = Some(child);
                        }
                    }
                }

                // Check which branches have returns
                let true_has_return = true_branch
                    .as_ref()
                    .map(|b| self.block_has_return(b))
                    .unwrap_or(false);
                let else_has_return = else_clause
                    .as_ref()
                    .map(|e| self.block_has_return(e))
                    .unwrap_or(false);

                // If this is a NULL check, mark the variable as null in the true branch
                if let Some(ref var_name) = null_check_var {
                    self.null_variables.insert(var_name.clone());
                }

                // If this is a truthiness check on a realloc result, mark old ptr as freed in true branch
                // e.g., if (new_ptr) { ... } where new_ptr = realloc(old_ptr, ...)
                if let Some(ref result_var) = truthiness_var {
                    if let Some(old_ptr) = self.realloc_relations.get(result_var).cloned() {
                        let pos = node.start_position();
                        self.freed_memory
                            .insert(old_ptr, (pos.row + 1, pos.column + 1));
                    }
                }
                // Also for explicit != NULL checks
                if let Some(ref result_var) = non_null_check_var {
                    if let Some(old_ptr) = self.realloc_relations.get(result_var).cloned() {
                        let pos = node.start_position();
                        self.freed_memory
                            .insert(old_ptr, (pos.row + 1, pos.column + 1));
                    }
                }

                // Process true branch
                if let Some(ref branch) = true_branch {
                    self.analyze_node(branch, source);
                }

                let true_freed = self.freed_memory.clone();
                let true_null = self.null_variables.clone();

                // Process else branch if present, or use saved state if no else
                let (else_freed, else_null) = if let Some(ref else_node) = else_clause {
                    // Reset to saved state for else branch
                    self.freed_memory = saved_freed.clone();
                    self.null_variables = saved_null.clone();

                    // For else clause, mark truthiness var as null
                    if let Some(ref var_name) = truthiness_var {
                        self.null_variables.insert(var_name.clone());
                    }
                    // Mark non-null check var as null in else branch
                    if let Some(ref var_name) = non_null_check_var {
                        self.null_variables.insert(var_name.clone());
                    }

                    self.analyze_node(else_node, source);
                    (self.freed_memory.clone(), self.null_variables.clone())
                } else {
                    // No else clause - the "else path" is just the saved state
                    (saved_freed.clone(), saved_null.clone())
                };

                // Determine final state based on which branches return
                if true_has_return && else_has_return {
                    // Both branches return - restore initial state
                    self.freed_memory = saved_freed;
                    self.null_variables = saved_null;
                } else if true_has_return {
                    // Only true returns - else branch state continues
                    self.freed_memory = else_freed;
                    self.null_variables = else_null;
                } else if else_has_return {
                    // Only else returns - true branch state continues
                    self.freed_memory = true_freed;
                    self.null_variables = true_null;
                } else if else_clause.is_some() {
                    // NEITHER branch returns and BOTH branches exist
                    // Check for conditional leaks: freed in one branch but not the other
                    let if_pos = node.start_position();
                    for (var_name, alloc_info) in &saved_allocated {
                        // Skip variables that shouldn't be checked
                        if self.escaped_memory.contains(var_name)
                            || saved_null.contains(var_name)
                            || var_name.contains('@')
                        {
                            continue;
                        }

                        let freed_in_true = true_freed.contains_key(var_name);
                        let freed_in_else = else_freed.contains_key(var_name);
                        let null_in_else = else_null.contains(var_name);

                        // Report leak only if freed in true but not else, and not null in else
                        if freed_in_true && !freed_in_else && !null_in_else {
                            self.leak_violations.push(RuleViolation {
                                rule_id: "MEM31-C".to_string(),
                                severity: Severity::High,
                                message: format!(
                                    "Conditional memory leak: '{}' allocated with '{}' is only freed in one branch",
                                    var_name, alloc_info.alloc_type
                                ),
                                file_path: String::new(),
                                line: if_pos.row + 1,
                                column: if_pos.column + 1,
                                suggestion: Some(format!(
                                    "Ensure '{}' is freed in both branches",
                                    var_name
                                )),
                                ..Default::default()
                            });
                        }
                    }
                    // Use UNION of both branches: if freed in either path, consider
                    // it freed. The conditional leak check above already reported
                    // the case where only one branch frees.
                    let mut merged = true_freed;
                    for (k, v) in else_freed {
                        merged.entry(k).or_insert(v);
                    }
                    self.freed_memory = merged;
                }
                // else: no else clause - just keep current state
            }
            "switch_statement" => {
                // For switch statements, each case is an independent path
                // Save state before the switch
                let saved_freed = self.freed_memory.clone();
                let saved_null = self.null_variables.clone();

                // Find the switch body and process each case
                if let Some(body) = node.child_by_field_name("body") {
                    for i in 0..body.child_count() {
                        if let Some(child) = body.child(i) {
                            if child.kind() == "case_statement" {
                                // Reset to saved state for each case
                                self.freed_memory = saved_freed.clone();
                                self.null_variables = saved_null.clone();
                                self.analyze_node(&child, source);
                            }
                        }
                    }
                }
            }
            "compound_statement" => {
                // Process compound statements recursively
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        self.analyze_node(&child, source);
                    }
                }
            }
            _ => {
                // Recursively process other nodes
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        self.analyze_node(&child, source);
                    }
                }
            }
        }
    }

    fn process_statement(&mut self, node: &Node, source: &str) {
        // Look for declarations with malloc/calloc/realloc
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(declarator) = child.child_by_field_name("declarator") {
                        let var_name = self.get_variable_name(&declarator, source);

                        if let Some(value) = child.child_by_field_name("value") {
                            if self.is_allocation_call(&value, source) {
                                let pos = value.start_position();
                                let alloc_type = self.get_allocation_type(&value, source);

                                // Special handling for realloc: track relationship for later
                                if alloc_type == "realloc" {
                                    self.handle_realloc_in_decl(&var_name, &value, source);
                                }

                                self.allocated_memory.insert(
                                    var_name.clone(),
                                    AllocInfo {
                                        line: pos.row + 1,
                                        column: pos.column + 1,
                                        alloc_type: alloc_type.clone(),
                                    },
                                );

                                // If signal handler has been registered, warn about potential leak
                                if self.signal_registered {
                                    self.leak_violations.push(RuleViolation {
                                        rule_id: "MEM31-C".to_string(),
                                        severity: Severity::High,
                                        message: format!(
                                            "Potential memory leak: '{}' allocated with '{}' may not be freed if signal handler terminates the program",
                                            var_name, alloc_type
                                        ),
                                        file_path: String::new(),
                                        line: pos.row + 1,
                                        column: pos.column + 1,
                                        suggestion: Some(format!(
                                            "Allocate '{}' before registering signal handlers, or ensure cleanup in signal handler",
                                            var_name
                                        )),
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                } else {
                    self.analyze_node(&child, source);
                }
            }
        }
    }

    /// Handle realloc when used in a declaration - tracks the relationship for later analysis
    fn handle_realloc_in_decl(&mut self, result_var: &str, call_node: &Node, source: &str) {
        // Handle cast expressions
        let actual_call = if call_node.kind() == "cast_expression" {
            call_node.child_by_field_name("value")
        } else {
            Some(*call_node)
        };

        if let Some(call) = actual_call {
            if call.kind() == "call_expression" {
                if let Some(arguments) = call.child_by_field_name("arguments") {
                    for i in 0..arguments.child_count() {
                        if let Some(arg) = arguments.child(i) {
                            if arg.kind() != "," && arg.kind() != "(" && arg.kind() != ")" {
                                // First argument to realloc is the old pointer
                                if arg.kind() == "identifier" {
                                    let old_ptr = ast_utils::get_node_text_owned(&arg, source);
                                    // Track: result_var was assigned from realloc(old_ptr)
                                    self.realloc_relations
                                        .insert(result_var.to_string(), old_ptr);
                                }
                                break; // Only process first argument
                            }
                        }
                    }
                }
            }
        }
    }

    fn process_assignment(&mut self, node: &Node, source: &str) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            // Handle field expressions on the left - track allocation if RHS is allocation
            // e.g., data->text = malloc(100) or array[i] = malloc(50)
            if left.kind() == "field_expression" || left.kind() == "subscript_expression" {
                // If right side is an allocation, track it with the full expression as key
                if self.is_allocation_call(&right, source) {
                    let var_name = ast_utils::get_node_text_owned(&left, source);
                    let pos = right.start_position();
                    let alloc_type = self.get_allocation_type(&right, source);
                    self.allocated_memory.insert(
                        var_name.clone(),
                        AllocInfo {
                            line: pos.row + 1,
                            column: pos.column + 1,
                            alloc_type,
                        },
                    );
                } else if right.kind() == "identifier" {
                    // If right side is an allocated variable, mark it as escaped
                    // e.g., list->head = new_node (new_node escapes)
                    let right_var = ast_utils::get_node_text_owned(&right, source);
                    if self.allocated_memory.contains_key(&right_var) {
                        self.escaped_memory.insert(right_var.clone());
                        // Also mark any field allocations belonging to this container as escaped
                        let field_prefix = format!("{}->", right_var);
                        let fields_to_escape: Vec<String> = self
                            .allocated_memory
                            .keys()
                            .filter(|k| k.starts_with(&field_prefix))
                            .cloned()
                            .collect();
                        for field in fields_to_escape {
                            self.escaped_memory.insert(field);
                        }
                    }
                }
                return;
            }

            // Handle identifiers for allocation tracking
            let var_name = if left.kind() == "identifier" {
                ast_utils::get_node_text_owned(&left, source)
            } else {
                return;
            };

            // Check if this variable was previously allocated
            let was_allocated = self.allocated_memory.contains_key(&var_name);

            // Check if assigning result of allocation
            if self.is_allocation_call(&right, source) {
                // If the variable was already allocated and not freed, it's a leak
                if was_allocated && !self.freed_memory.contains_key(&var_name) {
                    // The old allocation is now leaked - we need to create a unique identifier for it
                    // Since we can't track the old allocation separately, we'll generate a violation now
                    if let Some(old_alloc) = self.allocated_memory.get(&var_name) {
                        // We'll mark this as leaked by creating a unique name for the old allocation
                        let leaked_name =
                            format!("{}@{}:{}", var_name, old_alloc.line, old_alloc.column);
                        self.allocated_memory.insert(leaked_name, old_alloc.clone());
                    }
                }

                // New allocation clears freed status (variable now points to valid memory)
                self.freed_memory.remove(&var_name);

                let pos = right.start_position();
                let alloc_type = self.get_allocation_type(&right, source);
                self.allocated_memory.insert(
                    var_name.clone(),
                    AllocInfo {
                        line: pos.row + 1,
                        column: pos.column + 1,
                        alloc_type,
                    },
                );
            } else if right.kind() == "identifier" {
                // Check if assigning allocated pointer to another variable
                let right_var = ast_utils::get_node_text_owned(&right, source);

                // Assignment of one pointer to another clears the freed status
                // (e.g., buffer = temp after realloc)
                self.freed_memory.remove(&var_name);

                if self.allocated_memory.contains_key(&right_var) {
                    // Transfer ownership
                    if let Some(alloc_info) = self.allocated_memory.get(&right_var).cloned() {
                        self.allocated_memory.insert(var_name, alloc_info);
                        // The original variable still holds the allocation until freed
                    }
                }
            } else if right.kind() == "null"
                || ast_utils::get_node_text_owned(&right, source) == "NULL"
            {
                // Setting to NULL doesn't free memory, potential leak if not freed before
                // If the variable was allocated and not freed, it's a leak
                if was_allocated && !self.freed_memory.contains_key(&var_name) {
                    if let Some(old_alloc) = self.allocated_memory.get(&var_name) {
                        let leaked_name =
                            format!("{}@{}:{}", var_name, old_alloc.line, old_alloc.column);
                        self.allocated_memory.insert(leaked_name, old_alloc.clone());
                    }
                }
            }
        }
    }

    fn process_call(&mut self, node: &Node, source: &str) {
        let Some(function) = node.child_by_field_name("function") else {
            return;
        };
        let func_name = ast_utils::get_node_text_owned(&function, source);

        // Check for signal() registration - may lead to async termination
        if func_name == "signal" {
            self.signal_registered = true;
        }

        // Check for termination calls that leak memory
        if matches!(
            func_name.as_str(),
            "abort" | "exit" | "_Exit" | "_exit" | "quick_exit" | "longjmp" | "siglongjmp"
        ) {
            self.report_termination_leaks(node, &func_name);
            return;
        }

        // Check for custom deallocation functions: destroy_*, free_*, delete_*, cleanup_*, release_*
        if self.is_deallocation_call(&func_name) {
            self.process_custom_deallocator(node, source, &func_name);
        }

        if func_name == "free" {
            self.process_free_call(node, source);
        } else if func_name == "realloc" {
            self.process_realloc_call(node, source);
        } else {
            self.process_freeing_callee(node, source, &func_name);
        }
    }

    /// Report leaks of still-live allocations at a termination call (abort/exit/longjmp).
    fn report_termination_leaks(&mut self, node: &Node, func_name: &str) {
        let call_pos = node.start_position();

        for (var_name, alloc_info) in &self.allocated_memory {
            if self.escaped_memory.contains(var_name)
                || self.freed_memory.contains_key(var_name)
                || self.null_variables.contains(var_name)
                || var_name.contains('@')
            {
                continue;
            }

            self.leak_violations.push(RuleViolation {
                rule_id: "MEM31-C".to_string(),
                severity: Severity::High,
                message: format!(
                    "Memory leak: '{}' allocated with '{}' is not freed before {}()",
                    var_name, alloc_info.alloc_type, func_name
                ),
                file_path: String::new(),
                line: call_pos.row + 1,
                column: call_pos.column + 1,
                suggestion: Some(format!(
                    "Free '{}' before calling {}()",
                    var_name, func_name
                )),
                ..Default::default()
            });
        }
    }

    /// Handle a custom deallocator call (destroy_*, free_*, etc.): record double-frees
    /// for non-idempotent deallocators and mark the argument as freed.
    fn process_custom_deallocator(&mut self, node: &Node, source: &str, func_name: &str) {
        // Heuristic: functions with "safe" in the name or "destroy" prefix are typically
        // designed to be idempotent (set pointer to NULL after freeing)
        // Other custom deallocators like "cleanup_*" may not be safe to call twice
        let is_safe_deallocator = {
            let lower = func_name.to_lowercase();
            lower.contains("safe") || lower.starts_with("destroy_") || lower.ends_with("_destroy")
        };

        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        for i in 0..arguments.child_count() {
            let Some(arg) = arguments.child(i) else {
                continue;
            };
            let var_name = if arg.kind() == "pointer_expression" {
                // Handle &var pattern (address-of expression)
                arg.child_by_field_name("argument")
                    .filter(|op| op.kind() == "identifier")
                    .map(|op| ast_utils::get_node_text_owned(&op, source))
            } else if arg.kind() == "identifier" {
                Some(ast_utils::get_node_text_owned(&arg, source))
            } else {
                None
            };

            let Some(var_name) = var_name else {
                continue;
            };
            let free_pos = node.start_position();

            // Check for double-free only for non-safe deallocators
            if !is_safe_deallocator && self.freed_memory.contains_key(&var_name) {
                self.double_free_violations.push(RuleViolation {
                    rule_id: "MEM31-C".to_string(),
                    severity: Severity::High,
                    message: format!("Double free detected: '{}' was already freed", var_name),
                    file_path: String::new(),
                    line: free_pos.row + 1,
                    column: free_pos.column + 1,
                    suggestion: Some(format!(
                        "Remove this duplicate {}() call or set the pointer to NULL after first free",
                        func_name
                    )),
                    ..Default::default()
                });
            }

            // Mark as freed (for leak detection)
            self.freed_memory
                .insert(var_name.clone(), (free_pos.row + 1, free_pos.column + 1));
        }
    }

    /// Handle a `free()` call: record double-frees and mark the argument plus any
    /// aliases (same allocation site) as freed.
    fn process_free_call(&mut self, node: &Node, source: &str) {
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        for i in 0..arguments.child_count() {
            let Some(arg) = arguments.child(i) else {
                continue;
            };
            // Handle identifiers, field expressions, and subscript expressions
            let var_name = match arg.kind() {
                "identifier" | "field_expression" | "subscript_expression" => {
                    // For field/subscript expressions like "container->data" or "arr[i]"
                    ast_utils::get_node_text_owned(&arg, source)
                }
                _ => continue,
            };

            if var_name.is_empty() {
                continue;
            }
            let free_pos = node.start_position();

            // Check for double-free: if already freed, report violation
            if self.freed_memory.contains_key(&var_name) {
                self.double_free_violations.push(RuleViolation {
                    rule_id: "MEM31-C".to_string(),
                    severity: Severity::High,
                    message: format!("Double free detected: '{}' was already freed", var_name),
                    file_path: String::new(),
                    line: free_pos.row + 1,
                    column: free_pos.column + 1,
                    suggestion: Some(format!(
                        "Remove this duplicate free() call or set '{}' = NULL after first free",
                        var_name
                    )),
                    ..Default::default()
                });
            }

            // Mark as freed
            self.freed_memory
                .insert(var_name.clone(), (free_pos.row + 1, free_pos.column + 1));

            // Also mark any aliases as freed
            let vars_to_free: Vec<String> = self
                .allocated_memory
                .iter()
                .filter_map(|(k, v)| {
                    if let Some(original) = self.allocated_memory.get(&var_name) {
                        if v.line == original.line && v.column == original.column {
                            Some(k.clone())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect();

            for v in vars_to_free {
                self.freed_memory
                    .insert(v, (free_pos.row + 1, free_pos.column + 1));
            }
        }
    }

    /// Handle a `realloc()` call: the first argument's old memory is freed.
    fn process_realloc_call(&mut self, node: &Node, source: &str) {
        // realloc can be used to free memory (when new size is 0) or reallocate
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut arg_count = 0;
        let mut first_arg = String::new();
        let free_pos = node.start_position();

        for i in 0..arguments.child_count() {
            if let Some(arg) = arguments.child(i) {
                if arg.kind() != "," && arg.kind() != "(" && arg.kind() != ")" {
                    if arg_count == 0 && arg.kind() == "identifier" {
                        first_arg = ast_utils::get_node_text_owned(&arg, source);
                    }
                    arg_count += 1;
                }
            }
        }

        if !first_arg.is_empty() {
            // realloc frees the old memory and allocates new
            self.freed_memory
                .insert(first_arg.clone(), (free_pos.row + 1, free_pos.column + 1));
        }
    }

    /// Handle a call to a user function whose prescan summary indicates it frees
    /// one of its parameters: mark the matching allocated argument as freed.
    fn process_freeing_callee(&mut self, node: &Node, source: &str, func_name: &str) {
        // Check if passing allocated memory to a function that frees it.
        // Use prescan function summaries to determine if the callee frees
        // the parameter at the corresponding index.
        let Some(summary) = self.function_summaries.get(func_name) else {
            return;
        };
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut param_idx = 0usize;
        for i in 0..arguments.child_count() {
            if let Some(arg) = arguments.child(i) {
                if arg.kind() == "," || arg.kind() == "(" || arg.kind() == ")" {
                    continue;
                }
                if arg.kind() == "identifier" {
                    let var_name = ast_utils::get_node_text_owned(&arg, source);
                    if self.allocated_memory.contains_key(&var_name)
                        && summary.frees_params.contains(&param_idx)
                    {
                        let free_pos = node.start_position();
                        self.freed_memory
                            .insert(var_name, (free_pos.row + 1, free_pos.column + 1));
                    }
                }
                param_idx += 1;
            }
        }
    }

    fn process_return(&mut self, node: &Node, source: &str) {
        let return_pos = node.start_position();

        // If returning allocated memory, it escapes and shouldn't be considered a leak
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "identifier" {
                    let var_name = ast_utils::get_node_text_owned(&child, source);
                    if self.allocated_memory.contains_key(&var_name) {
                        self.escaped_memory.insert(var_name.clone());
                        // Also mark any field allocations belonging to this container as escaped
                        // e.g., if returning "person", mark "person->name" and "person->email" as escaped
                        let field_prefix = format!("{}->", var_name);
                        let fields_to_escape: Vec<String> = self
                            .allocated_memory
                            .keys()
                            .filter(|k| k.starts_with(&field_prefix))
                            .cloned()
                            .collect();
                        for field in fields_to_escape {
                            self.escaped_memory.insert(field);
                        }
                    }
                } else if self.is_allocation_call(&child, source) {
                    // Direct return of allocation is not a leak
                    // We don't track it since it escapes immediately
                }
            }
        }

        // Check for leaks at this return point
        for (var_name, alloc_info) in &self.allocated_memory {
            // Skip variables that are escaped, freed, null, or contain @ (leaked marker)
            if self.escaped_memory.contains(var_name)
                || self.freed_memory.contains_key(var_name)
                || self.null_variables.contains(var_name)
                || var_name.contains('@')
            {
                continue;
            }

            // Memory allocated but not freed at this return point - leak!
            self.leak_violations.push(RuleViolation {
                rule_id: "MEM31-C".to_string(),
                severity: Severity::High,
                message: format!(
                    "Memory leak: '{}' allocated with '{}' is not freed before return",
                    var_name, alloc_info.alloc_type
                ),
                file_path: String::new(),
                line: return_pos.row + 1,
                column: return_pos.column + 1,
                suggestion: Some(format!("Free '{}' before this return statement", var_name)),
                ..Default::default()
            });
        }
    }

    /// Check if an if_statement's condition is a truthiness check (if (ptr))
    /// Returns the variable name - ptr is NOT NULL in true branch, NULL in else branch
    fn get_truthiness_check_variable(&self, if_node: &Node, source: &str) -> Option<String> {
        if let Some(condition) = if_node.child_by_field_name("condition") {
            // Handle parenthesized expression
            let cond = if condition.kind() == "parenthesized_expression" {
                condition.child(1)?
            } else {
                condition
            };

            // Plain identifier or field_expression as condition means truthiness check
            // if (ptr) { ... } else { /* ptr is NULL here */ }
            if matches!(
                cond.kind(),
                "identifier" | "field_expression" | "subscript_expression"
            ) {
                return Some(ast_utils::get_node_text_owned(&cond, source));
            }
        }
        None
    }

    /// Check if an if_statement's condition is a NULL check (var == NULL)
    /// Returns the variable name if it's a NULL check
    fn get_null_check_variable(&self, if_node: &Node, source: &str) -> Option<String> {
        // Look for the condition node
        if let Some(condition) = if_node.child_by_field_name("condition") {
            // Handle parenthesized expression
            let cond = if condition.kind() == "parenthesized_expression" {
                condition.child(1)?
            } else {
                condition
            };

            // Look for binary_expression with == NULL or != NULL
            if cond.kind() == "binary_expression" {
                let op_text = cond
                    .child_by_field_name("operator")
                    .map(|op| ast_utils::get_node_text_owned(&op, source))
                    .unwrap_or_default();

                // Only handle == (var is NULL in true branch)
                if op_text == "==" {
                    let left = cond.child_by_field_name("left")?;
                    let right = cond.child_by_field_name("right")?;

                    let left_text = ast_utils::get_node_text_owned(&left, source);
                    let right_text = ast_utils::get_node_text_owned(&right, source);

                    // Check for var == NULL or NULL == var
                    // Handle identifier, field_expression, and subscript_expression
                    if right_text == "NULL" || right_text == "0" || right.kind() == "null" {
                        if matches!(
                            left.kind(),
                            "identifier" | "field_expression" | "subscript_expression"
                        ) {
                            return Some(left_text);
                        }
                    }
                    if left_text == "NULL" || left_text == "0" || left.kind() == "null" {
                        if matches!(
                            right.kind(),
                            "identifier" | "field_expression" | "subscript_expression"
                        ) {
                            return Some(right_text);
                        }
                    }
                }
            }

            // Handle unary NOT: if (!ptr) means ptr is falsy (NULL) in true branch
            if cond.kind() == "unary_expression" {
                let op_text = cond
                    .child_by_field_name("operator")
                    .map(|op| ast_utils::get_node_text_owned(&op, source))
                    .unwrap_or_default();

                if op_text == "!" {
                    if let Some(arg) = cond.child_by_field_name("argument") {
                        if matches!(
                            arg.kind(),
                            "identifier" | "field_expression" | "subscript_expression"
                        ) {
                            return Some(ast_utils::get_node_text_owned(&arg, source));
                        }
                    }
                }
            }
        }
        None
    }

    /// Check if an if_statement's condition is a non-NULL check (var != NULL)
    /// Returns the variable name if it's a non-NULL check
    /// For `if (ptr != NULL) { ... } else { ... }`, ptr is NOT NULL in true branch, NULL in else
    fn get_non_null_check_variable(&self, if_node: &Node, source: &str) -> Option<String> {
        // Look for the condition node
        if let Some(condition) = if_node.child_by_field_name("condition") {
            // Handle parenthesized expression
            let cond = if condition.kind() == "parenthesized_expression" {
                condition.child(1)?
            } else {
                condition
            };

            // Look for binary_expression with != NULL
            if cond.kind() == "binary_expression" {
                let op_text = cond
                    .child_by_field_name("operator")
                    .map(|op| ast_utils::get_node_text_owned(&op, source))
                    .unwrap_or_default();

                // Handle != (var is NOT NULL in true branch, NULL in else branch)
                if op_text == "!=" {
                    let left = cond.child_by_field_name("left")?;
                    let right = cond.child_by_field_name("right")?;

                    let left_text = ast_utils::get_node_text_owned(&left, source);
                    let right_text = ast_utils::get_node_text_owned(&right, source);

                    // Check for var != NULL or NULL != var
                    if right_text == "NULL" || right_text == "0" || right.kind() == "null" {
                        if matches!(
                            left.kind(),
                            "identifier" | "field_expression" | "subscript_expression"
                        ) {
                            return Some(left_text);
                        }
                    }
                    if left_text == "NULL" || left_text == "0" || left.kind() == "null" {
                        if matches!(
                            right.kind(),
                            "identifier" | "field_expression" | "subscript_expression"
                        ) {
                            return Some(right_text);
                        }
                    }
                }
            }
        }
        None
    }

    /// Check if a function name suggests it's a deallocation function
    fn is_deallocation_call(&self, func_name: &str) -> bool {
        let lower_name = func_name.to_lowercase();
        lower_name.starts_with("destroy_")
            || lower_name.starts_with("free_")
            || lower_name.starts_with("delete_")
            || lower_name.starts_with("cleanup_")
            || lower_name.starts_with("release_")
            || lower_name.starts_with("close_")
            || lower_name.ends_with("_destroy")
            || lower_name.ends_with("_free")
            || lower_name.ends_with("_delete")
            || lower_name.ends_with("_cleanup")
            || lower_name.ends_with("_release")
            || lower_name.ends_with("_close")
    }

    fn is_allocation_call(&self, node: &Node, source: &str) -> bool {
        // Handle cast expressions like (char *)malloc(...)
        if node.kind() == "cast_expression" {
            if let Some(value) = node.child_by_field_name("value") {
                return self.is_allocation_call(&value, source);
            }
        }

        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = ast_utils::get_node_text_owned(&function, source);

                // Standard allocation functions
                if matches!(
                    func_name.as_str(),
                    "malloc" | "calloc" | "realloc" | "strdup" | "strndup"
                ) {
                    return true;
                }

                // Heuristic: function names that suggest allocation
                let lower_name = func_name.to_lowercase();
                if lower_name.starts_with("create_")
                    || lower_name.starts_with("alloc_")
                    || lower_name.starts_with("new_")
                    || lower_name.starts_with("make_")
                    || lower_name.starts_with("build_")
                    || lower_name.ends_with("_alloc")
                    || lower_name.ends_with("_create")
                    || lower_name.ends_with("_new")
                    || lower_name.ends_with("_dup")
                {
                    return true;
                }
            }
        }
        false
    }

    fn get_allocation_type(&self, node: &Node, source: &str) -> String {
        // Handle cast expressions like (char *)malloc(...)
        if node.kind() == "cast_expression" {
            if let Some(value) = node.child_by_field_name("value") {
                return self.get_allocation_type(&value, source);
            }
        }

        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                return ast_utils::get_node_text_owned(&function, source);
            }
        }
        "unknown".to_string()
    }

    fn get_variable_name(&self, declarator: &Node, source: &str) -> String {
        match declarator.kind() {
            "identifier" => ast_utils::get_node_text_owned(declarator, source),
            "pointer_declarator" | "array_declarator" => {
                for i in 0..declarator.child_count() {
                    if let Some(child) = declarator.child(i) {
                        if child.kind() == "identifier" {
                            return ast_utils::get_node_text_owned(&child, source);
                        }
                        let nested_name = self.get_variable_name(&child, source);
                        if nested_name != "unknown" {
                            return nested_name;
                        }
                    }
                }
                "unknown".to_string()
            }
            _ => "unknown".to_string(),
        }
    }

    fn detect_leaks(&self, violations: &mut Vec<RuleViolation>) {
        for (var_name, alloc_info) in &self.allocated_memory {
            if !self.freed_memory.contains_key(var_name) && !self.escaped_memory.contains(var_name)
            {
                violations.push(RuleViolation {
                    rule_id: "MEM31-C".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Memory allocated with '{}' for variable '{}' is not freed",
                        alloc_info.alloc_type, var_name
                    ),
                    file_path: String::new(),
                    line: alloc_info.line,
                    column: alloc_info.column,
                    suggestion: Some(format!(
                        "Add 'free({})' before the variable goes out of scope",
                        var_name
                    )),
                    ..Default::default()
                });
            }
        }

        // Check for mismatched loop allocation/free patterns
        for (array_base, (alloc_cond, free_cond)) in &self.loop_array_patterns {
            if let (Some(alloc), Some(free)) = (alloc_cond, free_cond) {
                if alloc != free {
                    // Extract the numeric bounds if possible for a clearer message
                    violations.push(RuleViolation {
                        rule_id: "MEM31-C".to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Array '{}' elements allocated in loop with condition '{}' but freed with different condition '{}' - some elements may leak",
                            array_base, alloc, free
                        ),
                        file_path: String::new(),
                        line: 1,
                        column: 1,
                        suggestion: Some(format!(
                            "Ensure all elements of '{}' are freed with the same loop bounds used for allocation",
                            array_base
                        )),
                        ..Default::default()
                    });
                }
            } else if alloc_cond.is_some() && free_cond.is_none() {
                // Allocated in loop but not freed in any loop
                violations.push(RuleViolation {
                    rule_id: "MEM31-C".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Array '{}' elements allocated in loop but not freed in a matching loop - elements may leak",
                        array_base
                    ),
                    file_path: String::new(),
                    line: 1,
                    column: 1,
                    suggestion: Some(format!(
                        "Free all elements of '{}' in a loop with the same bounds",
                        array_base
                    )),
                    ..Default::default()
                });
            }
        }
    }

    /// Check if a node contains a return statement
    fn block_has_return(&self, node: &Node) -> bool {
        if node.kind() == "return_statement" {
            return true;
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if self.block_has_return(&child) {
                    return true;
                }
            }
        }

        false
    }
}
