use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::{self as cfg_mod, FunctionCfg};
use crate::analyze::context::ProjectContext;
use crate::analyze::function_summary::FunctionSummary;
use crate::analyze::null_state::{self, NullAnalysisResult, NullState, StateMap};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Exp34C {
    function_summaries: RefCell<HashMap<String, FunctionSummary>>,
    function_cfgs: RefCell<HashMap<usize, FunctionCfg>>,
    /// Null states for file-scope (static/global) pointer variables,
    /// computed once per file by scanning all declarations and assignments.
    file_global_states: RefCell<StateMap>,
    /// Cross-file global pointer null states from prescan.
    /// Used to resolve `extern` pointer globals defined in other translation units.
    prescan_global_var_states: RefCell<HashMap<String, NullState>>,
}

impl Exp34C {
    pub fn new() -> Self {
        Self {
            function_summaries: RefCell::new(HashMap::new()),
            function_cfgs: RefCell::new(HashMap::new()),
            file_global_states: RefCell::new(StateMap::new()),
            prescan_global_var_states: RefCell::new(HashMap::new()),
        }
    }
}

impl CertRule for Exp34C {
    fn rule_id(&self) -> &'static str {
        "EXP34-C"
    }

    fn description(&self) -> &'static str {
        "Do not dereference null pointers"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "EXP34-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
        *self.prescan_global_var_states.borrow_mut() = context.global_var_null_states.clone();
    }

    fn set_function_cfgs(&self, cfgs: &HashMap<usize, FunctionCfg>) {
        *self.function_cfgs.borrow_mut() = cfgs.clone();
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let summaries = self.function_summaries.borrow();
        let cfgs = self.function_cfgs.borrow();

        // At the top level (translation_unit), collect file-scope global null states
        if node.kind() == "translation_unit" {
            let mut globals = null_state::collect_file_scope_null_states(node, source, &summaries);

            // Merge prescan cross-file states for extern pointer declarations.
            // For variables declared `extern` in this file, the file-scope analysis
            // has no assignments to track — inject prescan-derived states.
            let prescan_states = self.prescan_global_var_states.borrow();
            if !prescan_states.is_empty() {
                merge_extern_global_states(node, source, &prescan_states, &mut globals);
            }

            *self.file_global_states.borrow_mut() = globals;
        }

        if node.kind() == "function_definition" {
            if let Some(body) = node.child_by_field_name("body") {
                // Get pre-built CFG or build one on the fly
                let inline_cfg;
                let cfg = if let Some(c) = cfgs.get(&node.start_byte()) {
                    c
                } else if let Some(c) = cfg_mod::build_function_cfg(node, source) {
                    inline_cfg = c;
                    &inline_cfg
                } else {
                    // Skip: no CFG available for this function
                    return violations;
                };

                // Extract function name for call-site param seeding
                let func_name = node
                    .child_by_field_name("declarator")
                    .and_then(|d| extract_function_name(&d, source));

                // Run CFG-based null-state dataflow, seeded with global states
                let global_states = self.file_global_states.borrow();
                let analysis = null_state::analyze_null_states_with_globals(
                    cfg,
                    node,
                    source,
                    &summaries,
                    &global_states,
                    func_name.as_deref(),
                );

                // Walk AST for dereferences and check each against the dataflow result
                let mut reported_vars: HashSet<String> = HashSet::new();
                check_dereferences_cfg(
                    &body,
                    source,
                    &analysis,
                    cfg,
                    &body,
                    &summaries,
                    &mut violations,
                    &mut reported_vars,
                );
            }
        }

        // Recursively check child nodes (handles nested functions, preproc blocks)
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                violations.extend(self.check(&child, source));
            }
        }

        violations
    }
}

// ---------------------------------------------------------------------------
// Dereference walker (AST-based, queries CFG analysis for safety)
// ---------------------------------------------------------------------------

fn check_dereferences_cfg(
    node: &Node,
    source: &str,
    analysis: &NullAnalysisResult,
    cfg: &FunctionCfg,
    body: &Node,
    summaries: &HashMap<String, FunctionSummary>,
    violations: &mut Vec<RuleViolation>,
    reported_vars: &mut HashSet<String>,
) {
    match node.kind() {
        "pointer_expression" => {
            // tree-sitter uses pointer_expression for both *ptr and &var.
            // Only dereference (*) can be a null-ptr bug.
            let is_deref = node
                .child_by_field_name("operator")
                .map(|op| ast_utils::get_node_text_owned(&op, source) == "*")
                .unwrap_or(false);

            if is_deref {
                if let Some(argument) = node.child_by_field_name("argument") {
                    let mut deref_text = ast_utils::get_node_text_owned(&argument, source);

                    // Strip parentheses
                    if argument.kind() == "parenthesized_expression" {
                        if let Some(inner) = argument.child(1) {
                            deref_text = ast_utils::get_node_text_owned(&inner, source);
                        }
                    }

                    if argument.kind() == "identifier"
                        || argument.kind() == "field_expression"
                        || argument.kind() == "parenthesized_expression"
                    {
                        if !reported_vars.contains(&deref_text)
                            && is_unsafe_at(
                                &deref_text,
                                node,
                                source,
                                analysis,
                                cfg,
                                body,
                                summaries,
                            )
                        {
                            reported_vars.insert(deref_text.clone());
                            let start_point = node.start_position();
                            violations.push(RuleViolation {
                                rule_id: "EXP34-C".to_string(),
                                severity: Severity::High,
                                message: format!(
                                    "Potential null pointer dereference of variable '{}'",
                                    deref_text
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some(format!(
                                    "Check if '{}' is not NULL before dereferencing",
                                    deref_text
                                )),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
        "subscript_expression" => {
            if let Some(array) = node.child(0) {
                if array.kind() == "identifier" {
                    let var_name = ast_utils::get_node_text_owned(&array, source);
                    if !reported_vars.contains(&var_name)
                        && is_unsafe_at(&var_name, node, source, analysis, cfg, body, summaries)
                    {
                        reported_vars.insert(var_name.clone());
                        let start_point = node.start_position();
                        violations.push(RuleViolation {
                            rule_id: "EXP34-C".to_string(),
                            severity: Severity::High,
                            message: format!(
                                "Potential null pointer dereference in array access of variable '{}'",
                                var_name
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(format!(
                                "Check if '{}' is not NULL before array access",
                                var_name
                            )),
                            ..Default::default()
                        });
                    }
                }
            }
        }
        "field_expression" => {
            if let Some(argument) = node.child_by_field_name("argument") {
                if argument.kind() == "identifier" {
                    let var_name = ast_utils::get_node_text_owned(&argument, source);
                    if !reported_vars.contains(&var_name)
                        && is_unsafe_at(&var_name, node, source, analysis, cfg, body, summaries)
                    {
                        reported_vars.insert(var_name.clone());
                        let start_point = node.start_position();
                        violations.push(RuleViolation {
                            rule_id: "EXP34-C".to_string(),
                            severity: Severity::High,
                            message: format!(
                                "Potential null pointer dereference in member access of variable '{}'",
                                var_name
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(format!(
                                "Check if '{}' is not NULL before member access",
                                var_name
                            )),
                            ..Default::default()
                        });
                    }
                }
            }
        }
        "call_expression" => {
            if let Some(function) = node.child_by_field_name("function") {
                // Function pointer call
                if function.kind() == "identifier" {
                    let func_name = ast_utils::get_node_text_owned(&function, source);
                    if !reported_vars.contains(&func_name)
                        && is_unsafe_at(&func_name, node, source, analysis, cfg, body, summaries)
                    {
                        reported_vars.insert(func_name.clone());
                        let start_point = function.start_position();
                        violations.push(RuleViolation {
                            rule_id: "EXP34-C".to_string(),
                            severity: Severity::High,
                            message: format!(
                                "Calling potentially null function pointer '{}'",
                                func_name
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(format!(
                                "Check if '{}' is not NULL before calling",
                                func_name
                            )),
                            ..Default::default()
                        });
                    }
                }

                // Check deref-function arguments. Skip when the callee is
                // known to accept NULL (free/fclose no-op on NULL per C standard).
                let func_name = ast_utils::get_node_text_owned(&function, source);
                if is_deref_function(&func_name) && !is_null_safe_function(&func_name) {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        check_function_arguments_cfg(
                            &args,
                            source,
                            analysis,
                            cfg,
                            body,
                            summaries,
                            violations,
                            reported_vars,
                        );
                    }
                }

                // Call-site null propagation: flag DefinitelyNull args to callees
                // that don't null-check them. Only when callee has a summary
                // (guards against flagging unknown library functions).
                if !is_deref_function(&func_name) && !is_null_safe_function(&func_name) {
                    if summaries.contains_key(&func_name) {
                        if let Some(args_node) = node.child_by_field_name("arguments") {
                            check_callsite_null_args(
                                &func_name, &args_node, source, analysis, cfg, body, summaries,
                                violations,
                            );
                        }
                    }
                }
            }
        }
        _ => {}
    }

    // Recurse
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            check_dereferences_cfg(
                &child,
                source,
                analysis,
                cfg,
                body,
                summaries,
                violations,
                reported_vars,
            );
        }
    }
}

fn check_function_arguments_cfg(
    args: &Node,
    source: &str,
    analysis: &NullAnalysisResult,
    cfg: &FunctionCfg,
    body: &Node,
    summaries: &HashMap<String, FunctionSummary>,
    violations: &mut Vec<RuleViolation>,
    reported_vars: &mut HashSet<String>,
) {
    for i in 0..args.child_count() {
        if let Some(arg) = args.child(i) {
            if arg.kind() == "identifier" {
                let var_name = ast_utils::get_node_text_owned(&arg, source);
                if !reported_vars.contains(&var_name)
                    && is_unsafe_at(&var_name, &arg, source, analysis, cfg, body, summaries)
                {
                    reported_vars.insert(var_name.clone());
                    let start_point = arg.start_position();
                    violations.push(RuleViolation {
                        rule_id: "EXP34-C".to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Passing potentially null pointer '{}' to function",
                            var_name
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(format!(
                            "Check if '{}' is not NULL before passing to function",
                            var_name
                        )),
                        ..Default::default()
                    });
                }
            }
        }
    }
}

/// Call-site null propagation: flag passing a DefinitelyNull pointer to a
/// function that doesn't null-check that parameter. This catches the source
/// side of cross-file null dereferences (Juliet variants 51-68).
fn check_callsite_null_args(
    callee_name: &str,
    args: &Node,
    source: &str,
    analysis: &NullAnalysisResult,
    cfg: &FunctionCfg,
    body: &Node,
    summaries: &HashMap<String, FunctionSummary>,
    violations: &mut Vec<RuleViolation>,
) {
    let callee_summary = summaries.get(callee_name);

    let mut param_idx: usize = 0;
    for i in 0..args.child_count() {
        if let Some(arg) = args.child(i) {
            // Skip commas and other non-argument tokens
            if arg.kind() == "," || arg.kind() == "(" || arg.kind() == ")" {
                continue;
            }

            if arg.kind() == "identifier" {
                let var_name = ast_utils::get_node_text_owned(&arg, source);
                let state = null_state::get_var_state_at(
                    analysis,
                    cfg,
                    body,
                    source,
                    &var_name,
                    arg.start_byte(),
                    summaries,
                );

                // Only flag DefinitelyNull — PossiblyNull is too noisy for call sites
                if state == null_state::NullState::DefinitelyNull {
                    // If no summary, assume callee handles null (conservative for unknowns)
                    let callee_checks_null = callee_summary
                        .map(|s| s.checks_null_params.contains(&param_idx))
                        .unwrap_or(true);

                    // Same rc<->out-parameter success correlation as is_unsafe_at:
                    // a pointer set through `&p` by a call whose status is stored
                    // in `rc`, then passed under an `rc == SQLITE_OK` guard, is
                    // non-null at the call. This interprocedural arg check does
                    // not route through is_unsafe_at, so apply the guard here too.
                    if !callee_checks_null && !is_guarded_by_rc_success(&var_name, &arg, source) {
                        let start_point = arg.start_position();
                        violations.push(RuleViolation {
                            rule_id: "EXP34-C".to_string(),
                            severity: Severity::High,
                            message: format!(
                                "Passing null pointer '{}' to '{}' which does not check for NULL",
                                var_name, callee_name
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(format!(
                                "Check if '{}' is not NULL before passing to '{}'",
                                var_name, callee_name
                            )),
                            ..Default::default()
                        });
                    }
                }
            }

            param_idx += 1;
        }
    }
}

/// Functions that safely handle NULL arguments (no dereference concern).
///
/// Includes:
/// - C standard: `free(NULL)` (C11 7.22.3.3) and `realloc(NULL, n)` (C11 7.22.3.5)
///   are defined as no-op / equivalent-to-malloc.
/// - Juliet test harness print helpers (null-tolerant stubs).
fn is_null_safe_function(name: &str) -> bool {
    matches!(
        name,
        "free"
            | "realloc"
            | "printLine"
            | "printWLine"
            | "printIntLine"
            | "printLongLine"
            | "printLongLongLine"
            | "printStructLine"
            | "printHexCharLine"
            | "printUnsignedLine"
            | "printFloatLine"
            | "printDoubleLine"
            | "printSizeTLine"
            | "printHexUnsignedCharLine"
    )
}

// ---------------------------------------------------------------------------
// Safety determination: CFG dataflow + AST expression guards
// ---------------------------------------------------------------------------

/// Check if dereferencing `var_name` at `deref_node` is unsafe.
/// Uses CFG dataflow as the primary check, with AST-based expression guards
/// for patterns that live within a single expression (&&, ternary).
fn is_unsafe_at(
    var_name: &str,
    deref_node: &Node,
    source: &str,
    analysis: &NullAnalysisResult,
    cfg: &FunctionCfg,
    body: &Node,
    summaries: &HashMap<String, FunctionSummary>,
) -> bool {
    let deref_byte = deref_node.start_byte();

    // A dereference inside `sizeof(...)` is never evaluated (unevaluated operand),
    // and one inside an `assert(...)` argument is a debug-only precondition check —
    // neither is a runtime null dereference. Suppress before consulting dataflow.
    if is_in_unevaluated_or_assert_context(deref_node, source) {
        return false;
    }

    // Primary check: CFG-based null state dataflow
    if !null_state::is_null_deref_at(analysis, cfg, body, source, var_name, deref_byte, summaries) {
        return false; // CFG says safe
    }

    // The CFG says potentially unsafe. But check AST-level expression guards
    // that the CFG cannot model (because they're within a single expression,
    // not separate CFG blocks).

    // Check && short-circuit: (ptr != NULL) && (ptr->field)
    // Check ternary: (ptr != NULL) ? *ptr : 0
    // Check if-statement scope (redundant with CFG for most cases, but catches
    // edge cases where CFG block boundaries don't align perfectly)
    if is_in_expression_guard(var_name, deref_node, source) {
        return false;
    }

    // rc<->out-parameter success correlation (the sqlite idiom):
    //   sqlite3_stmt *p = 0;
    //   rc = sqlite3_prepare(db, sql, -1, &p, 0);   // p set iff rc == SQLITE_OK
    //   if (rc == SQLITE_OK) { ... use p ... }       // or: while (rc==SQLITE_OK && step(p))
    // The pointer is assigned only through an out-parameter (&p) of a call whose
    // status is stored in `rc`, and the deref is dominated by an `rc == SQLITE_OK`
    // (== 0 / !rc) success guard. The null-state dataflow cannot correlate the
    // status code with the pointer, so it reports a spurious may-be-null. This is
    // distinct from the unguarded-malloc null-deref pattern (which has no status
    // guard and no out-parameter), so recall for that FN is unaffected.
    if is_guarded_by_rc_success(var_name, deref_node, source) {
        return false;
    }

    // A dereference of an iterator macro's loop variable inside the macro body
    // (e.g. `el->field` within `DL_FOREACH(head, el) { ... }`) is guarded
    // non-null by the macro's expanded loop condition, which the parser cannot
    // see. See crate::analyze::macro_semantics (Phase 1 of
    // docs/design/macro-expansion.md).
    if crate::analyze::macro_semantics::is_in_iterator_macro_body(deref_node, source, var_name) {
        return false;
    }

    true
}

/// Check if a dereference is guarded by expression-level null checks
/// that the CFG cannot model (&&, ternary) or by pragmatic null-check
/// patterns (if (ptr == NULL) { /* handle error */ } — no explicit return).
fn is_in_expression_guard(var_name: &str, node: &Node, source: &str) -> bool {
    let mut current = node.parent();

    while let Some(parent) = current {
        // Short-circuit guards:
        // && : (ptr != NULL) && (ptr->field) — right side safe when left confirms non-null
        // || : (ptr == NULL) || (ptr[0] == ...) — right side safe when left is null-check
        //      (right only evaluates when left is false, i.e. ptr is NOT null)
        if parent.kind() == "binary_expression" {
            if let Some(operator) = parent.child_by_field_name("operator") {
                let op = ast_utils::get_node_text_owned(&operator, source);
                if op == "&&" || op == "||" {
                    if let (Some(left), Some(right)) = (
                        parent.child_by_field_name("left"),
                        parent.child_by_field_name("right"),
                    ) {
                        // For &&: right executes when left is TRUE  → check left confirms non-null (negated=false)
                        // For ||: right executes when left is FALSE → check left negated confirms non-null (negated=true)
                        let negated = op == "||";
                        if node_is_within(&right, node)
                            && analyze_condition_for_safety(&left, var_name, source, negated)
                        {
                            return true;
                        }
                    }
                }
            }
        }

        // Ternary: (ptr != NULL) ? *ptr : default
        if parent.kind() == "conditional_expression" {
            if let Some(condition) = parent.child_by_field_name("condition") {
                if let Some(checked_var) = get_null_check_var(&condition, source) {
                    if checked_var == var_name {
                        let is_safe_in_consequence =
                            analyze_condition_for_safety(&condition, var_name, source, false);

                        if let Some(consequence) = parent.child_by_field_name("consequence") {
                            if node_is_within(&consequence, node) {
                                return is_safe_in_consequence;
                            }
                        }
                        if let Some(alternative) = parent.child_by_field_name("alternative") {
                            if node_is_within(&alternative, node) {
                                return !is_safe_in_consequence;
                            }
                        }
                    }
                }
            }
        }

        current = parent.parent();
    }

    // AST-level null guard: dereference inside if(var != NULL) { ... }
    // This handles cases where the CFG treats the enclosing context as a single
    // opaque block (e.g., inside switch_statement case bodies), so CFG-based
    // edge refinement cannot see the null guard.
    if is_inside_ast_null_guard(var_name, node, source) {
        return true;
    }

    // Pragmatic dominance check: if there's an if-statement earlier in the same
    // function that checks (var == NULL) and the dereference is AFTER that
    // if-statement, treat it as safe. This matches the common pattern:
    //   if (ptr == NULL) { /* Handle error */ }
    //   use(ptr);  // programmer assumes error was handled
    if is_dominated_by_null_check(var_name, node, source) {
        return true;
    }

    false
}

/// True when the node is in an unevaluated `sizeof(...)` operand or syntactically
/// inside an `assert(...)` argument. `sizeof` never evaluates its operand, and an
/// `assert(p->x)` is itself the precondition check (and is compiled out under
/// NDEBUG) — flagging a dereference in either context is a false positive.
fn is_in_unevaluated_or_assert_context(node: &Node, source: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "sizeof_expression" => return true,
            "call_expression"
                if parent
                    .child_by_field_name("function")
                    .map(|f| ast_utils::get_node_text_owned(&f, source) == "assert")
                    .unwrap_or(false) =>
            {
                return true;
            }
            "function_definition" => break,
            _ => {}
        }
        current = parent.parent();
    }
    false
}

/// Check if a dereference is inside the true branch of an `if(var != NULL)` statement.
/// Walks AST ancestors to find an enclosing if-statement that null-checks the variable.
fn is_inside_ast_null_guard(var_name: &str, node: &Node, source: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "function_definition" {
            break;
        }
        if parent.kind() == "if_statement" {
            if let Some(condition) = parent.child_by_field_name("condition") {
                if let Some(checked_var) = get_null_check_var(&condition, source) {
                    if checked_var == var_name {
                        // Check if we're in the consequence (true branch)
                        if let Some(consequence) = parent.child_by_field_name("consequence") {
                            if node_is_within(&consequence, node) {
                                // var != NULL → true branch means var is non-null → safe
                                if analyze_condition_for_safety(&condition, var_name, source, false)
                                {
                                    return true;
                                }
                            }
                        }
                        // Check if we're in the alternative (else branch)
                        if let Some(alternative) = parent.child_by_field_name("alternative") {
                            if node_is_within(&alternative, node) {
                                // var == NULL → true branch means null, else branch means non-null → safe
                                if !analyze_condition_for_safety(
                                    &condition, var_name, source, false,
                                ) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        current = parent.parent();
    }
    false
}

/// Walk up the AST to find the enclosing function body, then search for
/// if-statements that check `var_name == NULL` and occur before the
/// dereference (byte-position dominance).
fn is_dominated_by_null_check(var_name: &str, node: &Node, source: &str) -> bool {
    let deref_byte = node.start_byte();

    // Find the enclosing compound_statement (function body)
    let mut current = node.parent();
    let mut func_body = None;
    while let Some(parent) = current {
        if parent.kind() == "function_definition" {
            func_body = parent.child_by_field_name("body");
            break;
        }
        current = parent.parent();
    }

    let body = match func_body {
        Some(b) => b,
        None => return false,
    };

    // Search for if-statements that null-check this variable
    has_dominating_null_check(&body, var_name, deref_byte, source)
}

fn has_dominating_null_check(node: &Node, var_name: &str, deref_byte: usize, source: &str) -> bool {
    if node.kind() == "if_statement" {
        // Must be BEFORE the dereference
        if node.end_byte() <= deref_byte {
            if let Some(condition) = node.child_by_field_name("condition") {
                if let Some(checked_var) = get_null_check_var(&condition, source) {
                    if checked_var == var_name {
                        // Check that the condition checks FOR null (== NULL, !ptr)
                        if !analyze_condition_for_safety(&condition, var_name, source, false) {
                            return true;
                        }
                    }
                }
            }
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            // Don't search past the dereference point
            if child.start_byte() > deref_byte {
                break;
            }
            if has_dominating_null_check(&child, var_name, deref_byte, source) {
                return true;
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// rc<->out-parameter success correlation
// ---------------------------------------------------------------------------

/// True when `var_name` is dereferenced under a status-code success guard
/// (`rc == SQLITE_OK` / `rc == 0` / `!rc`) and was itself assigned only through
/// an out-parameter (`&var_name`) of a call whose status was stored in that same
/// guard variable. See the call site in `is_unsafe_at` for the full idiom.
fn is_guarded_by_rc_success(var_name: &str, node: &Node, source: &str) -> bool {
    let deref_byte = node.start_byte();

    // Walk ancestors to find a success guard that dominates the dereference,
    // capturing the status variable it tests.
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "function_definition" {
            break;
        }

        let guard_var = match parent.kind() {
            // while/if/for condition guards the body: cond holds inside it.
            "if_statement" | "while_statement" | "do_statement" => parent
                .child_by_field_name("condition")
                .and_then(|c| rc_success_guard_var(&c, source)),
            // `rc == SQLITE_OK && <expr deref'ing var>`: the deref is in the
            // right operand, the guard is the (whole) left operand.
            "binary_expression" => {
                let op = parent
                    .child_by_field_name("operator")
                    .map(|o| ast_utils::get_node_text_owned(&o, source));
                if op.as_deref() == Some("&&") {
                    parent
                        .child_by_field_name("left")
                        .filter(|left| !node_is_within(left, node))
                        .and_then(|left| rc_success_guard_var(&left, source))
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(rc) = guard_var {
            if var_assigned_via_rc_outparam(var_name, &rc, node, deref_byte, source) {
                return true;
            }
        }

        current = parent.parent();
    }

    false
}

/// If `cond` is (or contains, across `&&` conjuncts) a status-code success
/// test, return the status variable name. Recognises `X == SQLITE_OK`,
/// `SQLITE_OK == X`, `X == 0`, `0 == X`, and `!X`.
fn rc_success_guard_var(cond: &Node, source: &str) -> Option<String> {
    match cond.kind() {
        "parenthesized_expression" => cond
            .child(1)
            .and_then(|inner| rc_success_guard_var(&inner, source)),
        "unary_expression" => {
            // `!rc` → success
            let op = cond
                .child_by_field_name("operator")
                .map(|o| ast_utils::get_node_text_owned(&o, source));
            if op.as_deref() == Some("!") {
                cond.child_by_field_name("argument").and_then(|arg| {
                    if arg.kind() == "identifier" {
                        Some(ast_utils::get_node_text_owned(&arg, source))
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        }
        "binary_expression" => {
            let op = cond
                .child_by_field_name("operator")
                .map(|o| ast_utils::get_node_text_owned(&o, source))?;
            let left = cond.child_by_field_name("left")?;
            let right = cond.child_by_field_name("right")?;
            if op == "&&" {
                // Any conjunct may carry the success test.
                return rc_success_guard_var(&left, source)
                    .or_else(|| rc_success_guard_var(&right, source));
            }
            if op == "==" {
                return success_equality_var(&left, &right, source);
            }
            None
        }
        _ => None,
    }
}

/// For an `==` comparison, return the identifier operand when the other operand
/// is a success constant (`SQLITE_OK` or `0`).
fn success_equality_var(a: &Node, b: &Node, source: &str) -> Option<String> {
    let is_success_const = |n: &Node| {
        let t = ast_utils::get_node_text_owned(n, source);
        t == "SQLITE_OK" || t == "0"
    };
    if a.kind() == "identifier" && is_success_const(b) {
        return Some(ast_utils::get_node_text_owned(a, source));
    }
    if b.kind() == "identifier" && is_success_const(a) {
        return Some(ast_utils::get_node_text_owned(b, source));
    }
    None
}

/// True when, before `deref_byte` in the enclosing function, `var_name` is
/// taken by address (`&var_name`) inside a call expression whose result is
/// assigned (or initialised) into the status variable `rc`. Handles both
/// `rc = call(&var)` and `int rc = call(&var)`.
fn var_assigned_via_rc_outparam(
    var_name: &str,
    rc: &str,
    node: &Node,
    deref_byte: usize,
    source: &str,
) -> bool {
    // Find the enclosing function body.
    let mut current = node.parent();
    let mut func_body = None;
    while let Some(parent) = current {
        if parent.kind() == "function_definition" {
            func_body = parent.child_by_field_name("body");
            break;
        }
        current = parent.parent();
    }
    match func_body {
        Some(body) => find_rc_outparam_assignment(&body, var_name, rc, deref_byte, source),
        None => false,
    }
}

fn find_rc_outparam_assignment(
    node: &Node,
    var_name: &str,
    rc: &str,
    deref_byte: usize,
    source: &str,
) -> bool {
    // Out-parameter assignment must occur before the dereference.
    if node.start_byte() < deref_byte {
        // `rc = call(..., &var_name, ...)`
        if node.kind() == "assignment_expression" {
            if let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                if left.kind() == "identifier"
                    && ast_utils::get_node_text_owned(&left, source) == rc
                    && call_takes_address_of(&right, var_name, source)
                {
                    return true;
                }
            }
        }
        // `int rc = call(..., &var_name, ...)`
        if node.kind() == "init_declarator" {
            if let (Some(decl), Some(value)) = (
                node.child_by_field_name("declarator"),
                node.child_by_field_name("value"),
            ) {
                if ast_utils::get_node_text_owned(&decl, source) == rc
                    && call_takes_address_of(&value, var_name, source)
                {
                    return true;
                }
            }
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.start_byte() >= deref_byte {
                break;
            }
            if find_rc_outparam_assignment(&child, var_name, rc, deref_byte, source) {
                return true;
            }
        }
    }
    false
}

/// True when `expr` is a call expression that passes `&var_name` as an argument.
fn call_takes_address_of(expr: &Node, var_name: &str, source: &str) -> bool {
    let call = match expr.kind() {
        "call_expression" => *expr,
        // Unwrap a cast like `(int)call(...)`.
        _ => {
            let mut found = None;
            for i in 0..expr.child_count() {
                if let Some(c) = expr.child(i) {
                    if c.kind() == "call_expression" {
                        found = Some(c);
                        break;
                    }
                }
            }
            match found {
                Some(c) => c,
                None => return false,
            }
        }
    };
    let args = match call.child_by_field_name("arguments") {
        Some(a) => a,
        None => return false,
    };
    let target = format!("&{}", var_name);
    for i in 0..args.child_count() {
        if let Some(arg) = args.child(i) {
            if arg.kind() == "pointer_expression" {
                // Normalise whitespace: `& p` and `&p` both match.
                let t: String = ast_utils::get_node_text_owned(&arg, source)
                    .split_whitespace()
                    .collect();
                if t == target {
                    return true;
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Condition analysis helpers (used for expression-level guards)
// ---------------------------------------------------------------------------

fn get_null_check_var(condition: &Node, source: &str) -> Option<String> {
    match condition.kind() {
        "parenthesized_expression" => condition
            .child(1)
            .and_then(|c| get_null_check_var(&c, source)),
        "binary_expression" => {
            if let (Some(left), Some(right)) = (
                condition.child_by_field_name("left"),
                condition.child_by_field_name("right"),
            ) {
                let lt = ast_utils::get_node_text_owned(&left, source);
                let rt = ast_utils::get_node_text_owned(&right, source);
                if is_null_value(&rt) && left.kind() == "identifier" {
                    return Some(lt);
                }
                if is_null_value(&lt) && right.kind() == "identifier" {
                    return Some(rt);
                }
                if let Some(operator) = condition.child_by_field_name("operator") {
                    let op = ast_utils::get_node_text_owned(&operator, source);
                    if op == "||" || op == "&&" {
                        if let Some(var) = get_null_check_var(&left, source) {
                            return Some(var);
                        }
                        return get_null_check_var(&right, source);
                    }
                }
            }
            None
        }
        "unary_expression" => {
            if let Some(operand) = condition.child_by_field_name("argument") {
                if operand.kind() == "identifier" {
                    return Some(ast_utils::get_node_text_owned(&operand, source));
                }
            }
            None
        }
        "identifier" => Some(ast_utils::get_node_text_owned(condition, source)),
        _ => None,
    }
}

fn analyze_condition_for_safety(node: &Node, var_name: &str, source: &str, negated: bool) -> bool {
    match node.kind() {
        "parenthesized_expression" => {
            if let Some(child) = node.child(1) {
                return analyze_condition_for_safety(&child, var_name, source, negated);
            }
        }
        "unary_expression" => {
            if let Some(operator) = node.child(0) {
                if ast_utils::get_node_text_owned(&operator, source) == "!" {
                    if let Some(argument) = node.child_by_field_name("argument") {
                        return analyze_condition_for_safety(&argument, var_name, source, !negated);
                    }
                }
            }
        }
        "binary_expression" => {
            if let Some(operator) = node.child_by_field_name("operator") {
                let op = ast_utils::get_node_text_owned(&operator, source);
                match op.as_str() {
                    "==" if is_null_comparison(node, var_name, source) => {
                        return negated;
                    }
                    "!=" if is_null_comparison(node, var_name, source) => {
                        return !negated;
                    }
                    "&&" => {
                        if let (Some(left), Some(right)) = (
                            node.child_by_field_name("left"),
                            node.child_by_field_name("right"),
                        ) {
                            let l = analyze_condition_for_safety(&left, var_name, source, negated);
                            let r = analyze_condition_for_safety(&right, var_name, source, negated);
                            return l || r;
                        }
                    }
                    "||" => {
                        if let (Some(left), Some(right)) = (
                            node.child_by_field_name("left"),
                            node.child_by_field_name("right"),
                        ) {
                            let l = analyze_condition_for_safety(&left, var_name, source, negated);
                            let r = analyze_condition_for_safety(&right, var_name, source, negated);
                            return l && r;
                        }
                    }
                    _ => {}
                }
            }
        }
        "identifier" => {
            let text = ast_utils::get_node_text_owned(node, source);
            if text == var_name {
                return !negated;
            }
        }
        _ => {}
    }
    false
}

fn is_null_comparison(binary_expr: &Node, var_name: &str, source: &str) -> bool {
    if let (Some(left), Some(right)) = (
        binary_expr.child_by_field_name("left"),
        binary_expr.child_by_field_name("right"),
    ) {
        let lt = ast_utils::get_node_text_owned(&left, source);
        let rt = ast_utils::get_node_text_owned(&right, source);
        (lt == var_name && is_null_value(&rt)) || (rt == var_name && is_null_value(&lt))
    } else {
        false
    }
}

fn node_is_within(parent_node: &Node, child_node: &Node) -> bool {
    parent_node.start_byte() <= child_node.start_byte()
        && parent_node.end_byte() >= child_node.end_byte()
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn is_null_value(text: &str) -> bool {
    null_state::is_null_value(text)
}

/// Merge prescan cross-file global null states into the file-scope state map
/// for any `extern` pointer declarations found in this translation unit.
///
/// Scans top-level declarations for `extern TYPE *name;` and, if the variable
/// is still Unknown in `file_globals`, inserts the prescan-derived state.
fn merge_extern_global_states(
    root: &Node,
    source: &str,
    prescan_states: &HashMap<String, NullState>,
    file_globals: &mut StateMap,
) {
    merge_extern_in_node(root, source, prescan_states, file_globals);

    fn merge_extern_in_node(
        node: &Node,
        source: &str,
        prescan_states: &HashMap<String, NullState>,
        file_globals: &mut StateMap,
    ) {
        for i in 0..node.child_count() {
            let child = match node.child(i) {
                Some(c) => c,
                None => continue,
            };
            match child.kind() {
                "declaration" => {
                    let mut has_extern = false;
                    for j in 0..child.child_count() {
                        if let Some(tc) = child.child(j) {
                            if tc.kind() == "storage_class_specifier" {
                                if tc.utf8_text(source.as_bytes()).unwrap_or("") == "extern" {
                                    has_extern = true;
                                }
                            }
                        }
                    }
                    if !has_extern {
                        continue;
                    }
                    // Find pointer declarators in this extern declaration
                    for j in 0..child.child_count() {
                        if let Some(decl) = child.child(j) {
                            let name = match decl.kind() {
                                "pointer_declarator" => extract_id_from_decl(&decl, source),
                                "init_declarator" => {
                                    // Check child for pointer_declarator
                                    if has_pointer_child(&decl) {
                                        extract_id_from_decl(&decl, source)
                                    } else {
                                        continue;
                                    }
                                }
                                _ => continue,
                            };
                            if name.is_empty() {
                                continue;
                            }
                            // Only inject if not already resolved by file-scope analysis
                            let current = file_globals
                                .get(&name)
                                .copied()
                                .unwrap_or(NullState::Unknown);
                            if current == NullState::Unknown {
                                if let Some(&prescan_state) = prescan_states.get(&name) {
                                    file_globals.insert(name, prescan_state);
                                }
                            }
                        }
                    }
                }
                k if k.starts_with("preproc_") => {
                    merge_extern_in_node(&child, source, prescan_states, file_globals);
                }
                _ => {}
            }
        }
    }

    fn extract_id_from_decl(node: &Node, source: &str) -> String {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                match child.kind() {
                    "identifier" => {
                        return child.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                    }
                    "pointer_declarator" | "init_declarator" => {
                        let result = extract_id_from_decl(&child, source);
                        if !result.is_empty() {
                            return result;
                        }
                    }
                    _ => {}
                }
            }
        }
        String::new()
    }

    fn has_pointer_child(node: &Node) -> bool {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "pointer_declarator" {
                    return true;
                }
            }
        }
        false
    }
}

/// Extract the function name from a declarator node (handles pointer_declarator wrapping).
fn extract_function_name(declarator: &Node, source: &str) -> Option<String> {
    match declarator.kind() {
        "identifier" => {
            let name = ast_utils::get_node_text_owned(declarator, source);
            if name.is_empty() {
                None
            } else {
                Some(name)
            }
        }
        "function_declarator" | "pointer_declarator" => declarator
            .child_by_field_name("declarator")
            .and_then(|d| extract_function_name(&d, source)),
        _ => {
            for i in 0..declarator.child_count() {
                if let Some(child) = declarator.child(i) {
                    if child.kind() == "identifier" {
                        let name = ast_utils::get_node_text_owned(&child, source);
                        if !name.is_empty() {
                            return Some(name);
                        }
                    }
                }
            }
            None
        }
    }
}

fn is_deref_function(func_name: &str) -> bool {
    matches!(
        func_name,
        "strlen"
            | "strcpy"
            | "strcat"
            | "strcmp"
            | "strchr"
            | "strstr"
            | "sprintf"
            | "fprintf"
            | "printf"
            | "scanf"
            | "fscanf"
            | "fread"
            | "fwrite"
            | "fgets"
            | "fputs"
            | "fputc"
            | "fgetc"
            | "memcpy"
            | "memmove"
            | "memset"
            | "memcmp"
            | "free"
            | "fclose"
    )
}
