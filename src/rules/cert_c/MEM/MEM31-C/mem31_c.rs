use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::analyze::function_summary::{self, FunctionSummary};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
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
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            let mut analyzer = MemoryLeakAnalyzer::new(&summaries);
            analyzer.analyze_function(&func, source, &mut violations);
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
    // Names of this function's own parameters (task 306: a struct reached
    // through a bare parameter is caller-owned/borrowed — this function
    // populating one of its fields doesn't make this function responsible
    // for freeing it at return).
    function_params: HashSet<String>,
    // Parameters whose *pointee* was freshly allocated in this function via
    // a `*param = malloc(...)`-shaped out-parameter assignment. A struct
    // reached this way (e.g. `(*out)->field = malloc(...)`) IS this
    // function's own fresh allocation, not a borrowed caller struct, so it
    // stays a leak candidate.
    deref_allocated_params: HashSet<String>,
    // Local variables declared `static` (function-static storage
    // duration): CERT's own MEM31-C-EX2 exempts memory that's kept alive
    // for the remaining lifetime of the program, and a function-static
    // pointer used as a lazily-initialized cache (allocate once, reuse
    // across calls, never freed) is exactly that pattern -- not a leak
    // just because the function returns without freeing it.
    static_variables: HashSet<String>,
}

#[derive(Debug, Clone)]
struct AllocInfo {
    line: usize,
    column: usize,
    alloc_type: String,
}

/// The subset of `MemoryLeakAnalyzer`'s fields that are forked/reset/merged
/// across `if`/`switch` branches.
#[derive(Clone)]
struct LeakBranchState {
    freed_memory: HashMap<String, (usize, usize)>,
    null_variables: HashSet<String>,
}

impl LeakBranchState {
    fn fork(analyzer: &MemoryLeakAnalyzer) -> Self {
        Self {
            freed_memory: analyzer.freed_memory.clone(),
            null_variables: analyzer.null_variables.clone(),
        }
    }

    fn restore(&self, analyzer: &mut MemoryLeakAnalyzer) {
        analyzer.freed_memory = self.freed_memory.clone();
        analyzer.null_variables = self.null_variables.clone();
    }
}

// (alloc_info, free_info, loop_condition), as returned by
// `MemoryLeakAnalyzer::find_loop_array_pattern` plus the loop's own
// condition text.
type LoopArrayPattern = (
    Option<(String, bool)>,
    Option<(String, bool)>,
    Option<String>,
);

/// Explicit continuation-stack frames driving `MemoryLeakAnalyzer::
/// analyze_node` (task 295) — see that method's doc comment for why.
enum Frame<'a> {
    Visit(Node<'a>),
    /// Resume an `if`'s else-branch handling once the then-branch's own
    /// subtree (pushed on top of this frame) has fully drained.
    AfterTrueBranch {
        if_node: Node<'a>,
        saved_state: LeakBranchState,
        saved_allocated: HashMap<String, AllocInfo>,
        true_has_return: bool,
        else_has_return: bool,
        else_clause: Option<Node<'a>>,
        truthiness_var: Option<String>,
        non_null_check_var: Option<String>,
    },
    /// Merge then/else results once the else-branch's own subtree has fully
    /// drained.
    AfterElseBranch {
        if_node: Node<'a>,
        saved_state: LeakBranchState,
        saved_allocated: HashMap<String, AllocInfo>,
        true_has_return: bool,
        else_has_return: bool,
        true_state: LeakBranchState,
    },
    /// Reset to `pre_state` and walk the next `switch` case, once the
    /// previous case's own subtree has fully drained.
    SwitchNextCase {
        remaining_reversed: Vec<Node<'a>>,
        pre_state: LeakBranchState,
    },
    /// Decrement loop-nesting bookkeeping (and, for `for`, record the array
    /// alloc/free loop-condition pattern) once the loop body's own subtree
    /// has fully drained.
    ExitLoop {
        array_pattern: Option<LoopArrayPattern>,
    },
}

fn push_children<'a>(stack: &mut Vec<Frame<'a>>, node: &Node<'a>) {
    let count = node.child_count();
    for i in (0..count).rev() {
        if let Some(child) = node.child(i) {
            stack.push(Frame::Visit(child));
        }
    }
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
            function_params: HashSet::new(),
            deref_allocated_params: HashSet::new(),
            static_variables: HashSet::new(),
        }
    }

    fn analyze_function(
        &mut self,
        func_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(body) = func_node.child_by_field_name("body") {
            self.function_params = function_summary::collect_param_names(func_node, source)
                .into_iter()
                .filter(|n| !n.is_empty())
                .collect();
            self.static_variables = Self::collect_static_variable_names(&body, source);

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
        if is_alloc {
            // Looking for array[i] = malloc() pattern
            let assign = query::find_first_descendant(*node, |n| {
                n.kind() == "assignment_expression"
                    && n.child_by_field_name("left")
                        .is_some_and(|left| left.kind() == "subscript_expression")
                    && n.child_by_field_name("right")
                        .is_some_and(|right| self.is_allocation_call(&right, source))
            })?;
            let left = assign.child_by_field_name("left")?;
            // Extract array base (e.g., "array" from "array[i]")
            let base = left.child_by_field_name("argument")?;
            Some((ast_utils::get_node_text_owned(&base, source), true))
        } else {
            // Looking for free(array[i]) pattern
            let call = query::find_first_descendant(*node, |n| {
                if n.kind() != "call_expression" {
                    return false;
                }
                let Some(function) = n.child_by_field_name("function") else {
                    return false;
                };
                if ast_utils::get_node_text_owned(&function, source) != "free" {
                    return false;
                }
                let Some(arguments) = n.child_by_field_name("arguments") else {
                    return false;
                };
                (0..arguments.child_count())
                    .filter_map(|i| arguments.child(i))
                    .any(|arg| arg.kind() == "subscript_expression")
            })?;
            let arguments = call.child_by_field_name("arguments")?;
            let arg = (0..arguments.child_count())
                .filter_map(|i| arguments.child(i))
                .find(|arg| arg.kind() == "subscript_expression")?;
            let base = arg.child_by_field_name("argument")?;
            Some((ast_utils::get_node_text_owned(&base, source), true))
        }
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
                                    || self.static_variables.contains(var_name)
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

    /// Collect the names of local variables declared `static` within this
    /// function body -- their storage persists for the program's lifetime,
    /// so not freeing them before the function returns isn't a leak
    /// (MEM31-C-EX2).
    fn collect_static_variable_names(body: &Node, source: &str) -> HashSet<String> {
        let mut names = HashSet::new();
        for decl in query::find_descendants_of_kind(*body, "declaration") {
            let mut cursor = decl.walk();
            let is_static = decl.children(&mut cursor).any(|c| {
                c.kind() == "storage_class_specifier"
                    && ast_utils::get_node_text(&c, source) == "static"
            });
            if !is_static {
                continue;
            }
            let mut cursor = decl.walk();
            for child in decl.children(&mut cursor) {
                let declarator = match child.kind() {
                    "init_declarator" => child.child_by_field_name("declarator"),
                    "pointer_declarator" | "identifier" | "array_declarator" => Some(child),
                    _ => None,
                };
                if let Some(mut d) = declarator {
                    // Unwrap pointer_declarator layers to reach the identifier.
                    while d.kind() == "pointer_declarator" {
                        match d.child_by_field_name("declarator") {
                            Some(inner) => d = inner,
                            None => break,
                        }
                    }
                    if d.kind() == "identifier" {
                        names.insert(ast_utils::get_node_text(&d, source).to_string());
                    }
                }
            }
        }
        names
    }

    /// Pre-analyze function to find what variables are freed at each labeled statement
    fn collect_label_frees(&mut self, node: &Node, source: &str) {
        for label in query::find_descendants_of_kind(*node, "labeled_statement") {
            // Get the label name
            if let Some(label_node) = label.child(0) {
                if label_node.kind() == "statement_identifier" {
                    let label_name = ast_utils::get_node_text_owned(&label_node, source);
                    // Collect all free() calls reachable from this label
                    let mut freed_vars = HashSet::new();
                    self.collect_frees_in_label(&label, source, &mut freed_vars);
                    self.label_frees.insert(label_name, freed_vars);
                }
            }
        }
    }

    /// Collect all free() calls reachable from a labeled statement. Calls
    /// nested inside a `return` statement's own expression are excluded (a
    /// `return_statement` node prunes further descent into its children in
    /// the original recursive walk) — replicated here by filtering out any
    /// `call_expression` with a `return_statement` ancestor. A label can
    /// never be lexically nested inside a `return` expression in valid C, so
    /// walking the full (unbounded) ancestor chain from each call cannot
    /// cross above `node` and pick up an unrelated `return_statement`.
    fn collect_frees_in_label(&self, node: &Node, source: &str, freed_vars: &mut HashSet<String>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if query::find_ancestor(call, |a| a.kind() == "return_statement").is_some() {
                continue;
            }
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = ast_utils::get_node_text_owned(&function, source);
                if func_name == "free" {
                    if let Some(arguments) = call.child_by_field_name("arguments") {
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
    }

    /// Entry point: analyze a function body (or any subtree) using an
    /// explicit heap-allocated frame stack instead of native recursion
    /// (task 295). `analyze_node`/`analyze_children`/`analyze_if`/
    /// `analyze_switch`/`analyze_for_loop`/`analyze_simple_loop`/
    /// `process_statement` previously formed a mutually-recursive walk whose
    /// depth tracked C statement nesting — deeply/adversarially nested
    /// input (Juliet-style generated code) could overflow the native call
    /// stack. This is a pure mechanical conversion: dispatch, traversal
    /// order (left-to-right, preorder), and branch-merge policy for `if`
    /// (freed_memory/null_variables) are unchanged, including the
    /// pre-existing quirk that `analyze_switch` never merges/restores state
    /// after its last case (state is left as whatever that case produced).
    /// Note `analyze_children`'s original recursion, unlike MEM30-C's,
    /// never filtered out `#if 0` subtrees — that omission is preserved
    /// here too, not fixed under cover of this refactor.
    fn analyze_node(&mut self, node: &Node, source: &str) {
        let mut stack: Vec<Frame> = vec![Frame::Visit(*node)];
        while let Some(frame) = stack.pop() {
            match frame {
                Frame::Visit(n) => self.visit(n, source, &mut stack),
                Frame::AfterTrueBranch {
                    if_node,
                    saved_state,
                    saved_allocated,
                    true_has_return,
                    else_has_return,
                    else_clause,
                    truthiness_var,
                    non_null_check_var,
                } => self.after_true_branch(
                    if_node,
                    saved_state,
                    saved_allocated,
                    true_has_return,
                    else_has_return,
                    else_clause,
                    truthiness_var,
                    non_null_check_var,
                    &mut stack,
                ),
                Frame::AfterElseBranch {
                    if_node,
                    saved_state,
                    saved_allocated,
                    true_has_return,
                    else_has_return,
                    true_state,
                } => {
                    let else_state = LeakBranchState::fork(self);
                    Self::finish_if(
                        self,
                        &if_node,
                        &saved_state,
                        &saved_allocated,
                        true_has_return,
                        else_has_return,
                        &true_state,
                        &else_state,
                        true,
                    );
                }
                Frame::SwitchNextCase {
                    remaining_reversed,
                    pre_state,
                } => self.switch_next_case(remaining_reversed, pre_state, &mut stack),
                Frame::ExitLoop { array_pattern } => self.exit_loop(array_pattern),
            }
        }
    }

    /// Dispatch for a single visited node: leaf statements are handled
    /// directly; statements that need to suspend across a nested subtree
    /// (`if`/`switch`/loops) push continuation frames instead of recursing.
    fn visit<'n>(&mut self, n: Node<'n>, source: &str, stack: &mut Vec<Frame<'n>>) {
        match n.kind() {
            "declaration" | "expression_statement" => {
                self.visit_declaration_or_expr(n, source, stack)
            }
            "assignment_expression" => self.process_assignment(&n, source),
            "call_expression" => self.process_call(&n, source),
            "return_statement" => self.process_return(&n, source),
            "goto_statement" => self.analyze_goto(&n, source),
            "for_statement" => self.visit_for_statement(n, source, stack),
            "while_statement" | "do_statement" => self.visit_while_do_statement(stack, n),
            "if_statement" => self.visit_if_statement(n, source, stack),
            "switch_statement" => self.visit_switch_statement(n, stack),
            _ => push_children(stack, &n),
        }
    }

    /// `declaration`/`expression_statement`: `init_declarator` children are
    /// handled inline (no further traversal, matching the original); any
    /// other child is deferred onto the stack instead of a recursive
    /// `analyze_node` call, preserving left-to-right order.
    fn visit_declaration_or_expr<'n>(
        &mut self,
        n: Node<'n>,
        source: &str,
        stack: &mut Vec<Frame<'n>>,
    ) {
        // Check for macro calls that might hide early returns
        self.check_for_return_macro(&n, source);
        let mut pending: Vec<Node> = Vec::new();
        for i in 0..n.child_count() {
            if let Some(child) = n.child(i) {
                if child.kind() == "init_declarator" {
                    self.process_init_declarator_child(&child, source);
                } else {
                    pending.push(child);
                }
            }
        }
        for child in pending.into_iter().rev() {
            stack.push(Frame::Visit(child));
        }
    }

    fn visit_for_statement<'n>(&mut self, n: Node<'n>, source: &str, stack: &mut Vec<Frame<'n>>) {
        let loop_condition = n
            .child_by_field_name("condition")
            .map(|c| ast_utils::get_node_text_owned(&c, source));
        self.in_loop = true;
        self.loop_depth += 1;
        let alloc_info = self.find_loop_array_pattern(&n, source, true);
        let free_info = self.find_loop_array_pattern(&n, source, false);
        stack.push(Frame::ExitLoop {
            array_pattern: Some((alloc_info, free_info, loop_condition)),
        });
        push_children(stack, &n);
    }

    fn visit_while_do_statement<'n>(&mut self, stack: &mut Vec<Frame<'n>>, n: Node<'n>) {
        self.in_loop = true;
        self.loop_depth += 1;
        stack.push(Frame::ExitLoop {
            array_pattern: None,
        });
        push_children(stack, &n);
    }

    fn visit_if_statement<'n>(&mut self, n: Node<'n>, source: &str, stack: &mut Vec<Frame<'n>>) {
        let saved_state = LeakBranchState::fork(self);
        let saved_allocated = self.allocated_memory.clone();

        let null_check_var = self.get_null_check_variable(&n, source);
        let non_null_check_var = self.get_non_null_check_variable(&n, source);
        let truthiness_var = self.get_truthiness_check_variable(&n, source);

        let mut true_branch: Option<Node> = None;
        let mut else_clause: Option<Node> = None;
        for i in 0..n.child_count() {
            if let Some(child) = n.child(i) {
                if child.kind() == "compound_statement" && true_branch.is_none() {
                    true_branch = Some(child);
                } else if child.kind() == "else_clause" {
                    else_clause = Some(child);
                }
            }
        }

        let true_has_return = true_branch
            .as_ref()
            .map(|b| self.block_has_return(b))
            .unwrap_or(false);
        let else_has_return = else_clause
            .as_ref()
            .map(|e| self.block_has_return(e))
            .unwrap_or(false);

        if let Some(ref var_name) = null_check_var {
            self.null_variables.insert(var_name.clone());
        }
        self.clear_realloc_invalidation_if_related(&truthiness_var, n);
        self.clear_realloc_invalidation_if_related(&non_null_check_var, n);

        stack.push(Frame::AfterTrueBranch {
            if_node: n,
            saved_state,
            saved_allocated,
            true_has_return,
            else_has_return,
            else_clause,
            truthiness_var,
            non_null_check_var,
        });
        if let Some(branch) = true_branch {
            stack.push(Frame::Visit(branch));
        }
    }

    /// If `result_var` is a tracked realloc result, its old pointer's
    /// invalidation was already recorded when the realloc ran; a truthiness
    /// or non-NULL check on the result means the realloc succeeded, so the
    /// old pointer is (re-)treated as freed rather than dangling.
    fn clear_realloc_invalidation_if_related(
        &mut self,
        result_var: &Option<String>,
        if_node: Node,
    ) {
        let Some(result_var) = result_var else {
            return;
        };
        if let Some(old_ptr) = self.realloc_relations.get(result_var).cloned() {
            let pos = if_node.start_position();
            self.freed_memory
                .insert(old_ptr, (pos.row + 1, pos.column + 1));
        }
    }

    fn visit_switch_statement<'n>(&mut self, n: Node<'n>, stack: &mut Vec<Frame<'n>>) {
        let mut cases: Vec<Node> = Vec::new();
        if let Some(body) = n.child_by_field_name("body") {
            for i in 0..body.child_count() {
                if let Some(child) = body.child(i) {
                    if child.kind() == "case_statement" {
                        cases.push(child);
                    }
                }
            }
        }
        cases.reverse();
        stack.push(Frame::SwitchNextCase {
            remaining_reversed: cases,
            pre_state: LeakBranchState::fork(self),
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn after_true_branch<'n>(
        &mut self,
        if_node: Node<'n>,
        saved_state: LeakBranchState,
        saved_allocated: HashMap<String, AllocInfo>,
        true_has_return: bool,
        else_has_return: bool,
        else_clause: Option<Node<'n>>,
        truthiness_var: Option<String>,
        non_null_check_var: Option<String>,
        stack: &mut Vec<Frame<'n>>,
    ) {
        let true_state = LeakBranchState::fork(self);

        if let Some(else_node) = else_clause {
            saved_state.restore(self);
            if let Some(ref var_name) = truthiness_var {
                self.null_variables.insert(var_name.clone());
            }
            if let Some(ref var_name) = non_null_check_var {
                self.null_variables.insert(var_name.clone());
            }
            stack.push(Frame::AfterElseBranch {
                if_node,
                saved_state,
                saved_allocated,
                true_has_return,
                else_has_return,
                true_state,
            });
            stack.push(Frame::Visit(else_node));
        } else {
            // No else clause - the "else path" is just the saved state
            Self::finish_if(
                self,
                &if_node,
                &saved_state,
                &saved_allocated,
                true_has_return,
                else_has_return,
                &true_state,
                &saved_state,
                false,
            );
        }
    }

    fn switch_next_case<'n>(
        &mut self,
        mut remaining_reversed: Vec<Node<'n>>,
        pre_state: LeakBranchState,
        stack: &mut Vec<Frame<'n>>,
    ) {
        if let Some(case) = remaining_reversed.pop() {
            pre_state.restore(self);
            stack.push(Frame::SwitchNextCase {
                remaining_reversed,
                pre_state: pre_state.clone(),
            });
            stack.push(Frame::Visit(case));
        }
        // else: no more cases - chain ends, self stays as whatever the last
        // case left it (pre-existing quirk, preserved: no merge/restore
        // after the loop).
    }

    fn exit_loop(&mut self, array_pattern: Option<LoopArrayPattern>) {
        if let Some((alloc_info, free_info, loop_condition)) = array_pattern {
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
        }
        self.loop_depth -= 1;
        if self.loop_depth == 0 {
            self.in_loop = false;
        }
    }

    /// Merge post-then/post-else state back onto `analyzer` after an `if`,
    /// per which branch(es) unconditionally return, and report conditional
    /// leaks when neither returns and both branches exist. Direct
    /// transcription of the original `analyze_if`'s final merge block.
    #[allow(clippy::too_many_arguments)]
    fn finish_if(
        analyzer: &mut Self,
        if_node: &Node,
        saved_state: &LeakBranchState,
        saved_allocated: &HashMap<String, AllocInfo>,
        true_has_return: bool,
        else_has_return: bool,
        true_state: &LeakBranchState,
        else_state: &LeakBranchState,
        else_clause_present: bool,
    ) {
        if true_has_return && else_has_return {
            saved_state.restore(analyzer);
        } else if true_has_return {
            else_state.restore(analyzer);
        } else if else_has_return {
            true_state.restore(analyzer);
        } else if else_clause_present {
            analyzer.report_conditional_leaks(
                if_node,
                saved_allocated,
                &saved_state.null_variables,
                &true_state.freed_memory,
                &else_state.freed_memory,
                &else_state.null_variables,
            );
            let mut merged = true_state.freed_memory.clone();
            for (k, v) in else_state.freed_memory.clone() {
                merged.entry(k).or_insert(v);
            }
            analyzer.freed_memory = merged;
        }
        // else: no else clause - just keep current (true-branch) state
    }

    /// Inline body of the original `process_statement`'s `init_declarator`
    /// branch — allocation bookkeeping only, never recurses.
    fn process_init_declarator_child(&mut self, child: &Node, source: &str) {
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
    }

    /// A goto can bypass cleanup code; report leaks for allocations that aren't
    /// freed at the target label.
    fn analyze_goto(&mut self, node: &Node, source: &str) {
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
                || self.static_variables.contains(var_name)
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

    /// When neither `if` branch returns, report allocations freed in the true branch
    /// but not the else branch (and not nulled there) as conditional leaks.
    #[allow(clippy::too_many_arguments)]
    fn report_conditional_leaks(
        &mut self,
        node: &Node,
        saved_allocated: &HashMap<String, AllocInfo>,
        saved_null: &HashSet<String>,
        true_freed: &HashMap<String, (usize, usize)>,
        else_freed: &HashMap<String, (usize, usize)>,
        else_null: &HashSet<String>,
    ) {
        let if_pos = node.start_position();
        for (var_name, alloc_info) in saved_allocated {
            // Skip variables that shouldn't be checked
            if self.escaped_memory.contains(var_name)
                || saved_null.contains(var_name)
                || self.static_variables.contains(var_name)
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
                    suggestion: Some(format!("Ensure '{}' is freed in both branches", var_name)),
                    ..Default::default()
                });
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

    /// Walk down an lvalue expression (the target of a struct-field or
    /// array-element assignment) to find its root identifier, following
    /// `field_expression` -> `argument`, `subscript_expression` -> `argument`,
    /// `parenthesized_expression` unwrapping, and unary `*` dereference.
    /// Returns `(root_name, saw_deref)` where `saw_deref` is true if a `*`
    /// dereference or `[]` subscript was crossed en route to the root (task
    /// 306: distinguishes `cfg->field` — direct borrowed-struct-parameter
    /// access — from `(*out)->field` — an out-parameter pattern that may
    /// point at a struct this function itself just allocated).
    fn root_identifier_of_lvalue(&self, node: &Node, source: &str) -> Option<(String, bool)> {
        let mut current = *node;
        let mut saw_deref = false;
        loop {
            match current.kind() {
                "identifier" => {
                    return Some((ast_utils::get_node_text_owned(&current, source), saw_deref));
                }
                "field_expression" => {
                    current = current.child_by_field_name("argument")?;
                }
                "subscript_expression" => {
                    saw_deref = true;
                    current = current.child_by_field_name("argument")?;
                }
                "pointer_expression" => {
                    // `*p` and `&p` both parse as `pointer_expression` in
                    // this tree-sitter-c grammar (see points_to.rs), but
                    // `&p` can never appear as (part of) an lvalue chain --
                    // only `*p` can be assigned through -- so any
                    // pointer_expression reached while walking an
                    // assignment's LHS here is unambiguously a dereference.
                    saw_deref = true;
                    current = current.child_by_field_name("argument")?;
                }
                "parenthesized_expression" => {
                    current = current.named_child(0)?;
                }
                "unary_expression" => {
                    let op = current
                        .child_by_field_name("operator")
                        .map(|o| ast_utils::get_node_text_owned(&o, source))
                        .unwrap_or_default();
                    if op != "*" {
                        return None;
                    }
                    saw_deref = true;
                    current = current.child_by_field_name("argument")?;
                }
                _ => return None,
            }
        }
    }

    /// Is `left` (a struct-field/array-element lvalue) a leak candidate this
    /// function should be held responsible for, or does it reach into a
    /// caller-owned/borrowed struct via a bare function parameter (task
    /// 306)? A parameter's struct is only "owned" by this function if the
    /// parameter itself was used as an out-parameter that this function
    /// freshly allocated into (`*param = malloc(...)`); a plain
    /// `param->field = alloc()` is always borrowed.
    fn is_this_function_owned_field_target(&self, left: &Node, source: &str) -> bool {
        let Some((root, saw_deref)) = self.root_identifier_of_lvalue(left, source) else {
            // Couldn't determine a root identifier (unusual lvalue shape) -
            // preserve prior behavior and still track it.
            return true;
        };
        if !self.function_params.contains(&root) {
            return true;
        }
        saw_deref && self.deref_allocated_params.contains(&root)
    }

    /// Track `*param = malloc(...)`-shaped out-parameter allocations: this is
    /// the signal that a struct reached through `param` was freshly
    /// allocated by this function, not borrowed from the caller (task 306).
    fn record_deref_allocated_param(&mut self, left: &Node, right: &Node, source: &str) {
        let op = left
            .child_by_field_name("operator")
            .map(|o| ast_utils::get_node_text_owned(&o, source))
            .unwrap_or_default();
        if op != "*" || !self.is_allocation_call(right, source) {
            return;
        }
        let Some(arg) = left.child_by_field_name("argument") else {
            return;
        };
        if arg.kind() != "identifier" {
            return;
        }
        let name = ast_utils::get_node_text_owned(&arg, source);
        if self.function_params.contains(&name) {
            self.deref_allocated_params.insert(name);
        }
    }

    fn process_assignment(&mut self, node: &Node, source: &str) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            // `*out = malloc(...)` parses as "pointer_expression" in this
            // tree-sitter-c grammar, not "unary_expression" -- without this
            // arm, record_deref_allocated_param's out-parameter tracking
            // (task 306) never fired for the real dereference-assignment
            // pattern it exists to detect.
            if matches!(left.kind(), "unary_expression" | "pointer_expression") {
                self.record_deref_allocated_param(&left, &right, source);
                return;
            }

            // Handle field expressions on the left - track allocation if RHS is allocation
            // e.g., data->text = malloc(100) or array[i] = malloc(50)
            if left.kind() == "field_expression" || left.kind() == "subscript_expression" {
                // If right side is an allocation, track it with the full expression as key
                if self.is_allocation_call(&right, source) {
                    if !self.is_this_function_owned_field_target(&left, source) {
                        return;
                    }
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
                || self.static_variables.contains(var_name)
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
        let mut param_idx = 0usize;
        for i in 0..arguments.child_count() {
            let Some(arg) = arguments.child(i) else {
                continue;
            };
            if arg.kind() == "," || arg.kind() == "(" || arg.kind() == ")" {
                continue;
            }
            let this_param_idx = param_idx;
            param_idx += 1;
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

            // If the callee's summary shows it frees specific struct fields
            // off this parameter internally (e.g. `destroy_person(&p)` where
            // `destroy_person` does `free((*p)->name); free(*p);`), credit
            // those fields as freed here too — otherwise they read as leaks
            // even though ownership was transferred to the deallocator
            // (task 2: MEM31-C ownership model). `field` may itself be an
            // arrow-joined chain (e.g. "will->topic") for nested structs.
            if let Some(summary) = self.function_summaries.get(func_name) {
                if let Some(fields) = summary.frees_param_fields.get(&this_param_idx) {
                    for field in fields {
                        let field_key = format!("{}->{}", var_name, field);
                        self.freed_memory
                            .insert(field_key, (free_pos.row + 1, free_pos.column + 1));
                    }
                }
            }
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
            // Skip variables that are escaped, freed, null, static, or contain @ (leaked marker)
            if self.escaped_memory.contains(var_name)
                || self.freed_memory.contains_key(var_name)
                || self.null_variables.contains(var_name)
                || self.static_variables.contains(var_name)
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
        ast_utils::is_deallocation_call_name(func_name)
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

                // Inter-procedural: a user-defined wrapper whose body was
                // seen to malloc/calloc/realloc/aligned_alloc and return the
                // result (FunctionSummary.returns_allocation) is just as much
                // a fresh allocation as the literal/heuristic cases above.
                // Without this, reassigning through such a wrapper after a
                // free (e.g. `txt = octet_string_str(hash);`) never clears
                // freed_memory, so the next free(txt) is flagged as a false
                // double-free against stale state (task: MEM31-C wrapper
                // reassignment).
                if self
                    .function_summaries
                    .get(&func_name)
                    .is_some_and(|summary| summary.returns_allocation)
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
            if !self.freed_memory.contains_key(var_name)
                && !self.escaped_memory.contains(var_name)
                && !self.static_variables.contains(var_name)
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
        query::find_first_descendant(*node, |n| n.kind() == "return_statement").is_some()
    }
}
