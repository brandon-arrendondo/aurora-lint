//! API00-C: Functions should validate their parameters
//!
//! This rule detects functions that use parameters without validating them first.
//! This includes:
//! - Pointer parameters used without NULL checks
//! - Integer parameters used in arithmetic without overflow checks
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! void setfile(FILE *file) {
//!     myFile = file;  // No validation of file parameter
//! }
//!
//! int string_length(const char *str) {
//!     return strlen(str);  // No NULL check before use
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! errno_t setfile(FILE *file) {
//!     if (file && !ferror(file) && !feof(file)) {
//!         myFile = file;
//!         return 0;
//!     }
//!     return -1;  // Error handling
//! }
//!
//! int safe_string_copy(char *dest, const char *src) {
//!     if (!dest || !src) {
//!         return -1;  // Validation before use
//!     }
//!     strcpy(dest, src);
//!     return 0;
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find function definitions with pointer parameters
//! - Check if pointer parameters are validated (NULL check) before being used
//! - Report violation if a pointer parameter is used without prior validation

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::analyze::function_summary::FunctionSummary;
use crate::analyze::null_state::NullState;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{
    get_function_parameters, get_node_text, get_sanitized_node_text, is_pointer_type,
};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Api00C {
    function_summaries: RefCell<HashMap<String, FunctionSummary>>,
    dispatch_table_callbacks: RefCell<HashSet<String>>,
}

impl Api00C {
    pub fn new() -> Self {
        Self {
            function_summaries: RefCell::new(HashMap::new()),
            dispatch_table_callbacks: RefCell::new(HashSet::new()),
        }
    }
}

impl CertRule for Api00C {
    fn rule_id(&self) -> &'static str {
        "API00-C"
    }

    fn description(&self) -> &'static str {
        "Functions should validate their parameters"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "API00-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
        *self.dispatch_table_callbacks.borrow_mut() = context.dispatch_table_callbacks.clone();
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function_parameter_validation(&func, source, &mut violations);
        }
        violations
    }
}

impl Api00C {
    fn check_function_parameter_validation(
        &self,
        function_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Skip static functions — API00-C is about public API contracts
        if Self::is_static_function(function_node, source) {
            return;
        }

        // Skip dispatch-table-registered callbacks (task 594, extending task
        // 169's internal-contract suppression): a non-static function whose
        // name is registered as a bare value in an aggregate initializer
        // (e.g. pure-ftpd's `{ "mysql", pw_mysql_parse, pw_mysql_check,
        // pw_mysql_exit }` auth_list entry) and that is never invoked
        // directly by name anywhere in the project is reachable only through
        // the single indirect call site that walks that table. Its contract
        // is established at registration the same way a directly-called
        // internal helper's is — it isn't a public API entry point just
        // because it can't be marked `static` (cross-TU visibility is
        // required for the table to reference it).
        let func_name = self.get_function_name(function_node, source);
        if self.dispatch_table_callbacks.borrow().contains(&func_name) {
            return;
        }

        // Get function parameters (handle nested declarators for pointer-returning functions)
        let params = match self.extract_function_parameters(function_node, source) {
            Some(p) => p,
            None => return, // No parameters
        };

        // Check if this is a debug/logging function (has both file AND line parameters)
        let has_debug_params = params
            .iter()
            .any(|(name, _)| matches!(name.to_lowercase().as_str(), "file" | "filename"))
            && params
                .iter()
                .any(|(name, _)| matches!(name.to_lowercase().as_str(), "line" | "lineno"));

        // Check if this is a qsort-style comparator function
        // Pattern: int func(const void* a, const void* b, ...)
        let is_comparator = params.len() >= 2
            && params.iter().take(2).all(|(_, param_type)| {
                param_type.contains("const void *") || param_type.contains("const void*")
            });

        if is_comparator {
            return; // Skip validation for qsort-style comparators
        }

        // Filter for pointer parameters, excluding debug parameters only if this is a debug function
        let pointer_params: Vec<String> = params
            .iter()
            .filter(|(name, param_type)| {
                is_pointer_type(param_type)
                    && !(has_debug_params && self.is_debug_parameter(name))
                    && !self.is_callback_context_parameter(name)
            })
            .map(|(name, _)| name.clone())
            .collect();

        // Map param name → type text for downstream type-aware checks.
        let param_types: HashMap<&str, &str> = params
            .iter()
            .map(|(name, ty)| (name.as_str(), ty.as_str()))
            .collect();

        // Filter for integer parameters that could overflow
        let integer_params: Vec<String> = params
            .iter()
            .filter(|(_, param_type)| self.is_integer_type(param_type))
            .map(|(name, _)| name.clone())
            .collect();

        // Get function body
        let body = match function_node.child_by_field_name("body") {
            Some(b) => b,
            None => return, // No body (declaration only)
        };

        // Check pointer parameters
        if !pointer_params.is_empty() {
            // Find validated parameters (those that appear in validation checks)
            let validated_params = self.find_validated_parameters(&body, &pointer_params, source);

            // Look up callsite null states from prescan (if available)
            let func_name = self.get_function_name(function_node, source);
            let summaries = self.function_summaries.borrow();
            let summary = summaries.get(&func_name);

            // Build param name → index mapping
            let param_indices: HashMap<&str, usize> = params
                .iter()
                .enumerate()
                .map(|(i, (name, _))| (name.as_str(), i))
                .collect();

            // Check which pointer parameters are used without validation
            for param_name in &pointer_params {
                if !validated_params.contains(param_name) {
                    // Suppress if all callers pass NotNull for this parameter
                    if let (Some(s), Some(&idx)) = (summary, param_indices.get(param_name.as_str()))
                    {
                        if let Some(&state) = s.callsite_param_null_states.get(&idx) {
                            if state == NullState::NotNull {
                                continue; // All callers pass non-null → skip
                            }
                        }
                    }

                    // Suppress relay-only parameters: if the parameter is only
                    // passed as an argument to other function calls (never
                    // dereferenced, indexed, or member-accessed locally), the
                    // function is a relay and validation is the callee's concern.
                    if self.is_relay_only_parameter(&body, param_name, source) {
                        continue;
                    }

                    // Suppress `void *` parameters that are never dereferenced
                    // locally and pass through only to null-safe sinks. Typical
                    // generic-container slot parameter (e.g., ArrayList_Append's
                    // `void *item`) — NULL is a valid value.
                    if let Some(param_type) = param_types.get(param_name.as_str()) {
                        if Self::is_generic_void_pointer_type(param_type)
                            && self.is_void_ptr_storage_safe(&body, param_name, source, &summaries)
                        {
                            continue;
                        }
                    }

                    // Check if the parameter is actually used in the function
                    if self.is_parameter_used(&body, param_name, source) {
                        self.report_violation(
                            function_node,
                            param_name,
                            "pointer",
                            source,
                            violations,
                        );
                    }
                }
            }
        }

        // Check integer parameters for overflow validation
        if !integer_params.is_empty() {
            self.check_integer_overflow_validation(
                function_node,
                &body,
                &integer_params,
                source,
                violations,
            );
        }
    }

    /// Check if integer parameters are validated for overflow before arithmetic operations
    fn check_integer_overflow_validation(
        &self,
        function_node: &Node,
        body: &Node,
        integer_params: &[String],
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for arithmetic operations using integer parameters without overflow checks
        for param_name in integer_params {
            if self.has_unchecked_arithmetic(body, param_name, source) {
                self.report_violation(function_node, param_name, "integer", source, violations);
            }
        }
    }

    /// Check if an integer parameter is used in arithmetic without overflow validation
    fn has_unchecked_arithmetic(&self, body: &Node, param_name: &str, source: &str) -> bool {
        // Raw text is kept only for the two "will overflow"/"overflow check"
        // patterns below, which are intentionally designed to match a
        // developer's acknowledging comment. Every other substring check
        // uses the sanitized (comments/string/char literals blanked) text,
        // so a comment or string literal can't spoof a *code* pattern
        // (an INT_MAX comparison, an `if` guard, etc.) and silently
        // suppress a genuine violation.
        let raw_body_text = get_node_text(body, source);
        let body_no_comments = get_sanitized_node_text(body, source);
        let body_text = &body_no_comments;

        // Look for arithmetic operators with the parameter
        let arithmetic_patterns = [
            format!("{} +", param_name),
            format!("{} -", param_name),
            format!("{} *", param_name),
            format!("{}+", param_name),
            format!("{}-", param_name),
            format!("{}*", param_name),
            format!("+ {}", param_name),
            format!("- {}", param_name),
            format!("* {}", param_name),
            format!("+{}", param_name),
            format!("-{}", param_name),
            format!("*{}", param_name),
            format!("{} <<", param_name),
            format!("{}<<", param_name),
            format!("<< {}", param_name),
            format!("<<{}", param_name),
        ];

        let has_arithmetic = arithmetic_patterns
            .iter()
            .any(|p| body_no_comments.contains(p));

        if !has_arithmetic {
            return false;
        }

        // Check for overflow validation patterns
        let overflow_check_patterns = [
            // Check for INT_MAX/INT_MIN comparisons
            format!("{} > INT_MAX", param_name),
            format!("{} < INT_MIN", param_name),
            format!("{} >= INT_MAX", param_name),
            format!("{} <= INT_MIN", param_name),
            // Check for SIZE_MAX comparisons
            format!("{} > SIZE_MAX", param_name),
            format!("{} >= SIZE_MAX", param_name),
            format!("SIZE_MAX - {}", param_name),
            format!("SIZE_MAX -{}", param_name),
            // Check for UINT_MAX comparisons
            format!("{} > UINT_MAX", param_name),
            format!("{} >= UINT_MAX", param_name),
            // Wrapped arithmetic check
            "__builtin_add_overflow".to_string(),
            "__builtin_sub_overflow".to_string(),
            "__builtin_mul_overflow".to_string(),
        ];

        // "will overflow"/"overflow check" are meant to match a developer's
        // acknowledging comment, so these two look at the raw (unsanitized)
        // text on purpose.
        let has_overflow_check = overflow_check_patterns
            .iter()
            .any(|p| body_text.contains(p))
            || raw_body_text.contains("will overflow")
            || raw_body_text.contains("overflow check");

        // Also check for basic parameter validation (if param == 0, if param < X, etc.)
        let basic_validation_patterns = [
            format!("if ({} == 0)", param_name),
            format!("if ({}==0)", param_name),
            format!("if ({} == 0", param_name),
            format!("if (0 == {})", param_name),
            format!("if (!{})", param_name),
            format!("if ({} < ", param_name),
            format!("if ({} > ", param_name),
            format!("if ({} <= ", param_name),
            format!("if ({} >= ", param_name),
            // Handle || patterns
            format!("|| {} == 0", param_name),
            format!("||{} == 0", param_name),
            format!("{} == 0 ||", param_name),
            format!("{} == 0||", param_name),
            format!("|| {} > ", param_name),
            format!("|| {} < ", param_name),
            format!("{} > ", param_name),
            format!("{} < ", param_name),
        ];

        let has_basic_validation = basic_validation_patterns
            .iter()
            .any(|p| body_text.contains(p));

        // Detect the elapsed-time tick counter idiom: `current_tick() - param` where
        // unsigned wrap is intentional (C99 guarantees modular arithmetic for unsigned).
        // Recognise calls to getter functions whose names contain common tick/time patterns.
        let elapsed_time_pattern = [
            "Tick",
            "tick",
            "Time",
            "Clock",
            "clock",
            "Timestamp",
            "timestamp",
        ];
        let is_elapsed_time_subtraction = elapsed_time_pattern.iter().any(|kw| {
            // Look for `<tick_func>() - param_name` or `<tick_func>()- param_name`
            let sub_pat1 = format!("() - {}", param_name);
            let sub_pat2 = format!("()- {}", param_name);
            let sub_pat3 = format!("()-{}", param_name);
            (body_text.contains(&sub_pat1)
                || body_text.contains(&sub_pat2)
                || body_text.contains(&sub_pat3))
                && body_text.contains(kw)
        });

        if is_elapsed_time_subtraction {
            return false;
        }

        // Return true if there's arithmetic but no overflow check AND no basic validation
        !has_overflow_check && !has_basic_validation
    }

    /// Check if a type is an integer type (not floating point)
    fn is_integer_type(&self, type_str: &str) -> bool {
        let normalized = type_str.to_lowercase();
        // Exclude pointers
        if type_str.contains('*') {
            return false;
        }
        // Exclude floating point types
        if normalized.contains("float") || normalized.contains("double") {
            return false;
        }
        // Exclude char types — single-byte types used for character/byte processing
        // where arithmetic is on known-range values (e.g., c - '0', c - 'a')
        if normalized.contains("char") {
            return false;
        }
        // Check for integer types
        normalized.contains("int")
            || (normalized.contains("long") && !normalized.contains("double"))
            || normalized.contains("short")
            || normalized.contains("size_t")
            || (normalized.contains("unsigned")
                && !normalized.contains("double")
                && !normalized.contains("float"))
            || (normalized.contains("signed")
                && !normalized.contains("double")
                && !normalized.contains("float"))
    }

    /// Find parameters that are validated (checked for NULL) before use
    fn find_validated_parameters(
        &self,
        body: &Node,
        pointer_params: &[String],
        source: &str,
    ) -> HashSet<String> {
        let mut validated = HashSet::new();

        // Look for validation patterns at the start of the function
        self.check_validation_patterns(body, pointer_params, source, &mut validated);

        validated
    }

    /// Check for common validation patterns like:
    /// - if (!ptr) return;
    /// - if (ptr == NULL) return;
    /// - if (!ptr || !ptr2) return;
    ///
    /// Deliberately does NOT accept a bare `assert(ptr != NULL)`/`ASSERT(...)`
    /// as validation (task 646): assert calls compile to nothing under
    /// NDEBUG/release builds, so they don't satisfy API00-C's requirement
    /// that the check survive into production code. Confirmed empirically by
    /// task 644's full ground-truth re-audit: the single largest driver of
    /// mislabeled API00-C false positives was exactly this -- a compiled-out
    /// assert being credited as real validation.
    ///
    /// Uses an explicit stack instead of recursion: this only descends into
    /// preprocessor-block children, so it's bounded by preprocessor nesting
    /// depth (lower risk than the statement-chain cases in task 262), but
    /// still an unbounded native recursion in principle -- the same risk
    /// class as the original ARR00-C/MEM33-C bug (task 153) -- so it gets
    /// the same treatment for consistency.
    fn check_validation_patterns(
        &self,
        root: &Node,
        pointer_params: &[String],
        source: &str,
        validated: &mut HashSet<String>,
    ) {
        let mut stack = vec![*root];
        while let Some(node) = stack.pop() {
            for i in (0..node.child_count()).rev() {
                let Some(child) = node.child(i) else { continue };
                match child.kind() {
                    "if_statement" => self.check_if_statement_validation(
                        &child,
                        pointer_params,
                        source,
                        validated,
                    ),
                    "return_statement" => Self::check_return_statement_validation(
                        &child,
                        pointer_params,
                        source,
                        validated,
                    ),
                    // Queue preprocessor blocks — validation may be
                    // inside #ifdef/#if/#else branches
                    "preproc_ifdef"
                    | "preproc_if"
                    | "preproc_else"
                    | "preproc_elif"
                    | "preproc_function_def" => {
                        stack.push(child);
                    }
                    _ => {}
                }
            }
        }
    }

    /// `if_statement` case of [`check_validation_patterns`]: classify the
    /// guard as early-return, if/else split, or positive-guard, and record
    /// whichever params it validates.
    fn check_if_statement_validation(
        &self,
        child: &Node,
        pointer_params: &[String],
        source: &str,
        validated: &mut HashSet<String>,
    ) {
        let Some(condition) = child.child_by_field_name("condition") else {
            return;
        };
        let condition_text = get_node_text(&condition, source);

        // Case 1: early-return / early-exit pattern
        //   if (!ptr)        { return; }
        //   if (ptr == NULL) { return; }
        //   if (isNullOrEmpty(ptr)) { return; }  (helper fn call)
        if self.is_early_return_pattern(child, source) {
            // Use broad match: any param appearing in the condition
            // of an early-return guard is considered validated.
            // This handles both direct null checks and helper fn calls.
            for param in pointer_params {
                if condition_text.contains(param.as_str()) {
                    validated.insert(param.clone());
                }
            }
            return;
        }

        if child.child_by_field_name("alternative").is_some() {
            // Case 3: if/else chain — param is checked in condition and
            // actual work is in the else branch.
            //   if (NULL == ptr) { result = ERR; } else { work(ptr); }
            // Also handles if/else-if/else chains:
            //   if (NULL == a) { err; } else if (NULL == b) { err; } else { work(a,b); }
            let validated_in_condition =
                self.extract_validated_params_from_condition(&condition, pointer_params, source);
            for param in validated_in_condition {
                validated.insert(param);
            }
            // Walk into chained else-if conditions to collect more validated params
            self.collect_else_if_chain_validations(child, pointer_params, source, validated);
            return;
        }

        // Case 2: positive guard pattern
        //   if (ptr != NULL) { /* all usage inside */ }
        // The parameter is only accessed inside the guarded block,
        // so it is safely validated even without an early return.
        let validated_in_condition =
            self.extract_validated_params_from_condition(&condition, pointer_params, source);
        for param in validated_in_condition {
            if self.is_positive_null_guard(&condition_text, &param) {
                validated.insert(param);
            }
        }
    }

    /// `return_statement` case of [`check_validation_patterns`]: the null
    /// check IS the validation in short-circuit boolean returns, e.g.
    /// `return (str == NULL || str[0] == '\0');`.
    fn check_return_statement_validation(
        child: &Node,
        pointer_params: &[String],
        source: &str,
        validated: &mut HashSet<String>,
    ) {
        let stmt_text = get_node_text(child, source);
        for param in pointer_params {
            if stmt_text.contains(&format!("{} == NULL", param))
                || stmt_text.contains(&format!("NULL == {}", param))
                || stmt_text.contains(&format!("!{}", param))
                || stmt_text.contains(&format!("! {}", param))
            {
                validated.insert(param.clone());
            }
        }
    }

    /// Walk an if/else-if chain to collect validated params from all conditions.
    /// For `if (NULL == a) { err; } else if (NULL == b) { err; } else { work(a,b); }`,
    /// both `a` and `b` are validated in the final else block.
    /// Tree-sitter wraps else-if in `else_clause { if_statement { ... } }`.
    fn collect_else_if_chain_validations(
        &self,
        if_node: &Node,
        pointer_params: &[String],
        source: &str,
        validated: &mut HashSet<String>,
    ) {
        let mut current = *if_node;
        while let Some(alternative) = current.child_by_field_name("alternative") {
            // Tree-sitter wraps `else if` in an else_clause node
            let next_if = if alternative.kind() == "else_clause" {
                // Look for an if_statement inside the else_clause
                let mut inner_if = None;
                for i in 0..alternative.child_count() {
                    if let Some(child) = alternative.child(i) {
                        if child.kind() == "if_statement" {
                            inner_if = Some(child);
                            break;
                        }
                    }
                }
                match inner_if {
                    Some(if_stmt) => if_stmt,
                    None => break, // Plain else { ... } — end of chain
                }
            } else if alternative.kind() == "if_statement" {
                alternative
            } else {
                break;
            };

            if let Some(condition) = next_if.child_by_field_name("condition") {
                let params_in_cond = self.extract_validated_params_from_condition(
                    &condition,
                    pointer_params,
                    source,
                );
                for param in params_in_cond {
                    validated.insert(param);
                }
            }
            current = next_if;
        }
    }

    /// Extract parameter names that are being validated in a condition
    fn extract_validated_params_from_condition(
        &self,
        condition: &Node,
        pointer_params: &[String],
        source: &str,
    ) -> Vec<String> {
        let mut validated_params = Vec::new();
        let condition_text = get_node_text(condition, source);

        for param in pointer_params {
            // Check for common validation patterns:
            // !param, param == NULL, param != NULL (when combined with early return)
            // NULL == param, NULL != param
            // Also handle patterns with || separators

            // Create patterns to match
            let patterns = vec![
                format!("!{}", param),        // !ptr
                format!("! {}", param),       // ! ptr (with space)
                format!("{} == NULL", param), // ptr == NULL
                format!("NULL == {}", param), // NULL == ptr
                format!("{} == 0", param),    // ptr == 0
                format!("0 == {}", param),    // 0 == ptr
                format!("{}==NULL", param),   // ptr==NULL (no spaces)
                format!("NULL=={}", param),   // NULL==ptr
                format!("{} != NULL", param), // ptr != NULL (positive check)
                format!("NULL != {}", param), // NULL != ptr
                format!("{}!=NULL", param),   // ptr!=NULL
                format!("NULL!={}", param),   // NULL!=ptr
            ];

            let mut is_validated = false;
            for pattern in &patterns {
                if condition_text.contains(pattern) {
                    is_validated = true;
                    break;
                }
            }

            // Also check for parameter appearing in logical expressions
            // This handles: if (!a || !b || !c)
            if !is_validated {
                // Check if param appears with ! before it (possibly after ||)
                let search_patterns = vec![
                    format!("||!{}", param),  // ||!ptr
                    format!("|| !{}", param), // || !ptr
                    format!("(!{}", param),   // (!ptr
                    format!("( !{}", param),  // ( !ptr
                    format!("!{}||", param),  // !ptr||
                    format!("!{} ||", param), // !ptr ||
                    format!("!{})", param),   // !ptr)
                    format!("!{} )", param),  // !ptr )
                ];

                for pattern in &search_patterns {
                    if condition_text.contains(pattern) {
                        is_validated = true;
                        break;
                    }
                }
            }

            // Check for positive validation (parameter being checked for truthiness)
            // e.g., if (file && !ferror(file)), or bare if(ptr) / if (ptr)
            if !is_validated {
                let positive_patterns = vec![
                    format!("{} &&", param),  // ptr &&
                    format!("({}&&", param),  // (ptr&&
                    format!("({} &&", param), // (ptr &&
                    format!("&& {}", param),  // && ptr
                    format!("&&{}", param),   // &&ptr
                ];

                for pattern in &positive_patterns {
                    if condition_text.contains(pattern) {
                        is_validated = true;
                        break;
                    }
                }

                // Bare truthiness: condition IS the parameter itself
                // e.g., if(ptr) { use } else { return NULL; }
                if !is_validated {
                    let trimmed = condition_text.trim();
                    // Strip outer parens: "(ptr)" → "ptr"
                    let inner = if trimmed.starts_with('(') && trimmed.ends_with(')') {
                        trimmed[1..trimmed.len() - 1].trim()
                    } else {
                        trimmed
                    };
                    if inner == param {
                        is_validated = true;
                    }
                }
            }

            if is_validated {
                validated_params.push(param.clone());
            }
        }

        validated_params
    }

    /// Check if an if statement represents an early return/error pattern
    fn is_early_return_pattern(&self, if_node: &Node, source: &str) -> bool {
        // Get the consequence (then branch)
        if let Some(consequence) = if_node.child_by_field_name("consequence") {
            return self.contains_return_or_error(&consequence, source);
        }
        false
    }

    /// Check if a node contains a return statement or error handling
    fn contains_return_or_error(&self, node: &Node, source: &str) -> bool {
        match node.kind() {
            "return_statement" => true,
            "compound_statement" => {
                // Check ALL statements for return or noreturn function calls
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "return_statement" {
                            return true;
                        }
                        // Check for noreturn functions (longjmp, exit, abort)
                        if child.kind() == "expression_statement" {
                            if self.is_noreturn_call(&child, source) {
                                return true;
                            }
                        }
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Check if an expression statement contains a noreturn function call
    fn is_noreturn_call(&self, expr_stmt: &Node, source: &str) -> bool {
        for i in 0..expr_stmt.child_count() {
            if let Some(child) = expr_stmt.child(i) {
                if child.kind() == "call_expression" {
                    if let Some(func) = child.child_by_field_name("function") {
                        let func_name = get_node_text(&func, source);
                        // Check for common noreturn functions
                        if matches!(
                            func_name,
                            "longjmp" | "exit" | "abort" | "_Exit" | "quick_exit" | "thrd_exit"
                        ) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if a parameter is actually used in the function body
    /// Check if a parameter is only relayed to callees that validate it.
    /// Returns true when the parameter is never directly used and every callee
    /// that receives it either checks for null or itself relays to a checker.
    fn is_relay_only_parameter(&self, body: &Node, param_name: &str, source: &str) -> bool {
        let summaries = self.function_summaries.borrow();
        let mut relay_callees: Vec<(String, usize)> = Vec::new();
        let mut found_direct_use = false;
        self.classify_param_uses(
            body,
            param_name,
            source,
            &mut relay_callees,
            &mut found_direct_use,
        );
        if found_direct_use || relay_callees.is_empty() {
            return false;
        }
        // Every callee that receives this parameter must validate it or accept NULL
        for (callee_name, arg_idx) in &relay_callees {
            // Standard library functions that accept NULL pointers — no validation needed
            if Self::is_null_accepting_stdlib(callee_name, *arg_idx) {
                continue;
            }
            if let Some(callee_summary) = summaries.get(callee_name.as_str()) {
                if !callee_summary.checks_null_params.contains(arg_idx) {
                    return false; // Callee doesn't validate → not safe to suppress
                }
            } else {
                return false; // Unknown callee → not safe
            }
        }
        true
    }

    fn classify_param_uses(
        &self,
        node: &Node,
        param_name: &str,
        source: &str,
        relay_callees: &mut Vec<(String, usize)>,
        found_direct_use: &mut bool,
    ) {
        for ident in query::find_descendants_of_kind(*node, "identifier") {
            let text = get_node_text(&ident, source);
            if text != param_name {
                continue;
            }
            if let Some(parent) = ident.parent() {
                // Check: is this inside a call_expression's argument list?
                if parent.kind() == "argument_list" {
                    if let Some(call_expr) = parent.parent() {
                        if call_expr.kind() == "call_expression" {
                            if let Some(func) = call_expr.child_by_field_name("function") {
                                let callee = get_node_text(&func, source);
                                // Determine which positional arg this is
                                let arg_idx = self.get_arg_index(&ident, &parent);
                                relay_callees.push((callee.to_string(), arg_idx));
                                continue;
                            }
                        }
                    }
                    *found_direct_use = true;
                    continue;
                }
                if self.is_in_validation_context(&ident) || self.is_in_void_cast(&ident, source) {
                    continue;
                }
            }
            *found_direct_use = true;
        }
    }

    /// Get the positional index of an argument within an argument_list.
    /// Standard library functions that accept NULL pointer arguments by design.
    /// free(NULL) is a no-op per C11 7.22.3.3. realloc(NULL, size) is equivalent
    /// to malloc(size) per C11 7.22.3.5. These functions do NOT need callers to
    /// validate pointer arguments before calling.
    fn is_null_accepting_stdlib(func_name: &str, arg_idx: usize) -> bool {
        matches!(
            (func_name, arg_idx),
            ("free", 0)
                | ("realloc", 0)
                | ("cfree", 0)
                | ("Memory_Free", 0)
                | ("Memory_Realloc", 0)
        )
    }

    /// Return true if `param_type` is a bare `void *` (optionally const-qualified).
    /// Rejects `void **`, arrays, and anything with a concrete type name.
    fn is_generic_void_pointer_type(param_type: &str) -> bool {
        let trimmed = param_type.trim();
        if trimmed.contains('[') {
            return false;
        }
        if trimmed.chars().filter(|c| *c == '*').count() != 1 {
            return false;
        }
        if !trimmed.contains("void") {
            return false;
        }
        // The text before the `*` must contain only void / const / volatile tokens.
        let before_star = trimmed.split('*').next().unwrap_or("").trim();
        for token in before_star.split_whitespace() {
            if !matches!(token, "const" | "volatile" | "void") {
                return false;
            }
        }
        true
    }

    /// Walk the body and decide whether every use of a `void *` parameter is
    /// safe for a NULL value. Safe uses: stored as RHS of an assignment, used
    /// as a local initializer, passed to a null-accepting stdlib function, or
    /// passed to a callee whose summary validates the corresponding argument.
    /// A single dereference (`*item`, `item->x`, `item[i]`) or a call to a
    /// callee of unknown null-handling behavior makes the parameter unsafe.
    fn is_void_ptr_storage_safe(
        &self,
        body: &Node,
        param_name: &str,
        source: &str,
        summaries: &HashMap<String, FunctionSummary>,
    ) -> bool {
        let mut saw_any_use = false;
        let mut safe = true;
        self.void_ptr_storage_walk(
            body,
            param_name,
            source,
            summaries,
            &mut safe,
            &mut saw_any_use,
        );
        // If the parameter never appears, `is_parameter_used` will return false
        // anyway; don't claim responsibility for that path.
        saw_any_use && safe
    }

    fn void_ptr_storage_walk(
        &self,
        node: &Node,
        param_name: &str,
        source: &str,
        summaries: &HashMap<String, FunctionSummary>,
        safe: &mut bool,
        saw_any_use: &mut bool,
    ) {
        for ident in query::find_descendants_of_kind(*node, "identifier") {
            if !*safe {
                break;
            }
            let text = get_node_text(&ident, source);
            if text != param_name {
                continue;
            }
            *saw_any_use = true;
            if let Some(parent) = ident.parent() {
                // Skip identifiers that are used as a struct field name or
                // subscript index rather than as the dereference target —
                // those are unrelated uses of the same identifier text.
                let is_self_as_target = |field: &str| {
                    parent
                        .child_by_field_name(field)
                        .map(|t| t.id() == ident.id())
                        .unwrap_or(false)
                };
                match parent.kind() {
                    "pointer_expression" => {
                        // Could be `*item` (deref) or `&item` (address-of).
                        // Address-of a pointer itself doesn't deref it, but
                        // the resulting `void **` is highly atypical and we
                        // treat it as unsafe conservatively.
                        *safe = false;
                        continue;
                    }
                    "field_expression" if is_self_as_target("argument") => {
                        *safe = false;
                        continue;
                    }
                    "subscript_expression" if is_self_as_target("argument") => {
                        *safe = false;
                        continue;
                    }
                    "argument_list" => {
                        if let Some(call_expr) = parent.parent() {
                            if call_expr.kind() == "call_expression" {
                                if let Some(func) = call_expr.child_by_field_name("function") {
                                    let callee = get_node_text(&func, source);
                                    let arg_idx = self.get_arg_index(&ident, &parent);
                                    if Self::is_null_accepting_stdlib(callee, arg_idx) {
                                        // ok
                                    } else if let Some(s) = summaries.get(callee) {
                                        if !s.checks_null_params.contains(&arg_idx) {
                                            *safe = false;
                                            continue;
                                        }
                                    } else {
                                        *safe = false;
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                    "cast_expression" => {
                        // `(void *)item` or `(T *)item` — a cast is still just a
                        // value read, treat it as storage-like and keep walking.
                    }
                    _ => {
                        // Other parents: assignment RHS, initializer in a
                        // declaration, return expression, comparison, etc.
                        // All safe for a NULL value.
                    }
                }
            }
        }
    }

    fn get_arg_index(&self, arg_node: &Node, arg_list: &Node) -> usize {
        let mut idx = 0;
        for i in 0..arg_list.child_count() {
            if let Some(child) = arg_list.child(i) {
                if child.kind() == "(" || child.kind() == ")" || child.kind() == "," {
                    continue;
                }
                if child.id() == arg_node.id() {
                    return idx;
                }
                idx += 1;
            }
        }
        idx
    }

    fn is_parameter_used(&self, body: &Node, param_name: &str, source: &str) -> bool {
        query::find_first_descendant(*body, |node| {
            // Check if this node is an identifier matching the parameter name
            if node.kind() != "identifier" {
                return false;
            }
            let text = get_node_text(&node, source);
            if text != param_name {
                return false;
            }
            // Skip (void)param / UNUSED(param) patterns — these explicitly mark
            // a parameter as intentionally unused (e.g., callback signature match)
            if self.is_in_void_cast(&node, source) {
                return false;
            }
            // Check if it's actually being used (not just in a validation check)
            if let Some(parent) = node.parent() {
                // Skip if this is part of a validation check condition
                if !self.is_in_validation_context(&node) {
                    return true;
                }
                // Still count dereference as usage even in validation context
                if parent.kind() == "pointer_expression"
                    || parent.kind() == "field_expression"
                    || parent.kind() == "subscript_expression"
                {
                    return true;
                }
            }
            false
        })
        .is_some()
    }

    /// Check if a node is part of a validation context (if condition checking for NULL)
    fn is_in_validation_context(&self, node: &Node) -> bool {
        let mut current = node.parent();
        let mut depth = 0;

        while let Some(parent) = current {
            depth += 1;
            if depth > 10 {
                break; // Avoid infinite loops
            }

            // If we're in a parenthesized expression within an if condition
            if parent.kind() == "if_statement" {
                return true;
            }

            // Check for binary expressions that are comparisons to NULL
            if parent.kind() == "binary_expression" {
                return true;
            }

            // Check for unary not operator
            if parent.kind() == "unary_expression" {
                return true;
            }

            current = parent.parent();
        }

        false
    }

    /// Check if an identifier is inside a (void)param or UNUSED(param) cast.
    /// These patterns explicitly suppress unused-parameter warnings and indicate
    /// the parameter is intentionally not used.
    fn is_in_void_cast(&self, node: &Node, source: &str) -> bool {
        let mut current = node.parent();
        let mut depth = 0;

        while let Some(parent) = current {
            depth += 1;
            if depth > 5 {
                break;
            }

            if parent.kind() == "cast_expression" {
                // Check if the cast target type is "void"
                for i in 0..parent.child_count() {
                    if let Some(child) = parent.child(i) {
                        if child.kind() == "type_descriptor" {
                            let type_text = get_node_text(&child, source);
                            if type_text.trim() == "void" {
                                return true;
                            }
                        }
                    }
                }
            }

            // Handle UNUSED(param) macro — parsed as call_expression before preprocessing
            if parent.kind() == "call_expression" {
                if let Some(func) = parent.child_by_field_name("function") {
                    let func_name = get_node_text(&func, source);
                    if matches!(
                        func_name,
                        "UNUSED"
                            | "UNREFERENCED_PARAMETER"
                            | "UNUSED_PARAM"
                            | "UNUSED_PARAMETER"
                            | "Q_UNUSED"
                    ) {
                        return true;
                    }
                }
            }

            // Stop at expression_statement boundary
            if parent.kind() == "expression_statement" {
                break;
            }

            current = parent.parent();
        }

        false
    }

    /// Check if a function_definition has `static` storage class or a STATIC macro prefix.
    fn is_static_function(function_node: &Node, source: &str) -> bool {
        for i in 0..function_node.child_count() {
            if let Some(child) = function_node.child(i) {
                if child.kind() == "storage_class_specifier" {
                    if let Ok(text) = child.utf8_text(source.as_bytes()) {
                        if text == "static" {
                            return true;
                        }
                    }
                }
            }
        }
        // Check for STATIC macro prefix (tree-sitter sees unexpanded macro as first tokens).
        // Match any token in the declaration prefix that contains "STATIC" as a
        // substring — covers project-specific macros like LIN_STATIC_INLINE,
        // MY_STATIC_FUNC, etc.
        let func_text = function_node.utf8_text(source.as_bytes()).unwrap_or("");
        let before_paren = func_text.split('(').next().unwrap_or("");
        before_paren.split_whitespace().any(|token| {
            let t = token.trim_start_matches('*');
            t.contains("STATIC") || matches!(t, "PRIVATE" | "INTERNAL" | "LOCAL")
        })
    }

    fn report_violation(
        &self,
        function_node: &Node,
        param_name: &str,
        param_type: &str,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get function name
        let func_name = self.get_function_name(function_node, source);

        let (message, suggestion) = if param_type == "pointer" {
            (
                format!(
                    "Function '{}' does not validate pointer parameter '{}' before use",
                    func_name, param_name
                ),
                format!(
                    "Add validation check for '{}' at the start of the function, e.g., 'if (!{}) {{ return error_code; }}'",
                    param_name, param_name
                ),
            )
        } else {
            (
                format!(
                    "Function '{}' does not validate integer parameter '{}' for overflow before arithmetic operations",
                    func_name, param_name
                ),
                format!(
                    "Add overflow validation for '{}' before arithmetic, e.g., check against INT_MAX/INT_MIN or use __builtin_*_overflow()",
                    param_name
                ),
            )
        };

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::Medium,
            message,
            file_path: String::new(),
            line: function_node.start_position().row + 1,
            column: function_node.start_position().column + 1,
            suggestion: Some(suggestion),
            ..Default::default()
        });
    }

    fn get_function_name(&self, function_node: &Node, source: &str) -> String {
        // Find the function declarator
        for i in 0..function_node.child_count() {
            if let Some(child) = function_node.child(i) {
                if child.kind() == "function_declarator" {
                    // Get the identifier from the declarator
                    for j in 0..child.child_count() {
                        if let Some(declarator_child) = child.child(j) {
                            if declarator_child.kind() == "identifier" {
                                return get_node_text(&declarator_child, source).to_string();
                            }
                            // Handle pointer declarators like void (*func)(...)
                            if declarator_child.kind() == "parenthesized_declarator" {
                                if let Some(inner) = self.find_identifier(&declarator_child, source)
                                {
                                    return inner;
                                }
                            }
                        }
                    }
                } else if child.kind() == "pointer_declarator" {
                    // Handle functions returning pointers
                    if let Some(name) = self.find_identifier(&child, source) {
                        return name;
                    }
                }
            }
        }
        "unknown".to_string()
    }

    fn find_identifier(&self, node: &Node, source: &str) -> Option<String> {
        query::find_first_descendant(*node, |n| n.kind() == "identifier")
            .map(|n| get_node_text(&n, source).to_string())
    }

    /// Extract function parameters, handling nested declarators for pointer-returning functions
    fn extract_function_parameters(
        &self,
        function_node: &Node,
        source: &str,
    ) -> Option<Vec<(String, String)>> {
        // First try the standard utility
        if let Some(params) = get_function_parameters(function_node, source) {
            return Some(params);
        }

        // Handle pointer-returning functions (e.g., URL *parse_url(...))
        // The structure is: function_definition > pointer_declarator > function_declarator
        for i in 0..function_node.child_count() {
            if let Some(child) = function_node.child(i) {
                if child.kind() == "pointer_declarator" {
                    // Look for function_declarator inside
                    if let Some(params) = self.find_params_in_declarator(&child, source) {
                        return Some(params);
                    }
                }
            }
        }

        None
    }

    fn find_params_in_declarator(
        &self,
        node: &Node,
        source: &str,
    ) -> Option<Vec<(String, String)>> {
        let declarator =
            query::find_first_descendant(*node, |n| n.kind() == "function_declarator")?;
        self.extract_params_from_declarator(&declarator, source)
    }

    fn extract_params_from_declarator(
        &self,
        declarator_node: &Node,
        source: &str,
    ) -> Option<Vec<(String, String)>> {
        let mut parameters = Vec::new();

        // Find parameter_list node
        for i in 0..declarator_node.child_count() {
            if let Some(child) = declarator_node.child(i) {
                if child.kind() == "parameter_list" {
                    // Extract each parameter
                    for j in 0..child.child_count() {
                        if let Some(param) = child.child(j) {
                            if param.kind() == "parameter_declaration" {
                                let param_text = get_node_text(&param, source);
                                if let Some(name) = self.extract_param_name(&param, source) {
                                    parameters.push((name, param_text.to_string()));
                                }
                            }
                        }
                    }
                }
            }
        }

        if parameters.is_empty() {
            None
        } else {
            Some(parameters)
        }
    }

    fn extract_param_name(&self, param_node: &Node, source: &str) -> Option<String> {
        // Look for identifier or declarator pattern
        for i in 0..param_node.child_count() {
            if let Some(child) = param_node.child(i) {
                if child.kind() == "identifier" {
                    return Some(get_node_text(&child, source).to_string());
                } else if matches!(
                    child.kind(),
                    "array_declarator" | "pointer_declarator" | "function_declarator"
                ) {
                    // Recursively find identifier in declarator
                    if let Some(id) = self.find_identifier(&child, source) {
                        return Some(id);
                    }
                }
            }
        }
        None
    }

    /// Returns true if the condition text is a positive NULL guard for `param`,
    /// i.e. the if-block is only entered when the pointer is non-NULL.
    /// Examples: `ptr != NULL`, `NULL != ptr`, `ptr != 0`, `ptr` (bare truthiness)
    fn is_positive_null_guard(&self, condition_text: &str, param: &str) -> bool {
        let patterns: &[&str] = &["!= NULL", "!=NULL", "!= 0", "!=0"];
        for suffix in patterns {
            if condition_text.contains(&format!("{} {}", param, suffix))
                || condition_text.contains(&format!("{}{}", param, suffix))
            {
                return true;
            }
        }
        // NULL/0 on the left: NULL != ptr, 0 != ptr
        let prefixes: &[&str] = &["NULL !=", "NULL!=", "0 !=", "0!="];
        for prefix in prefixes {
            if condition_text.contains(&format!("{} {}", prefix, param))
                || condition_text.contains(&format!("{}{}", prefix, param))
            {
                return true;
            }
        }
        // Bare truthiness check: if (ptr) or if (ptr && ...)
        // but NOT if (!ptr) which is the early-return form already handled above
        let bare_patterns: &[&str] = &[
            &format!("({})", param),
            &format!("({} ", param),
            &format!("({} &&", param),
            &format!("({}&& ", param),
        ];
        for p in bare_patterns {
            if condition_text.contains(*p) {
                return true;
            }
        }
        false
    }

    /// Check if a parameter is a debug/logging parameter (e.g., __FILE__, __func__)
    /// These are commonly passed without validation
    fn is_debug_parameter(&self, param_name: &str) -> bool {
        matches!(
            param_name.to_lowercase().as_str(),
            "file" | "filename" | "func" | "function" | "function_name" | "line" | "lineno"
        )
    }

    /// Check if a parameter is a callback/handler context parameter.
    /// These are opaque data pointers passed through event dispatch systems
    /// and are not intended to be validated by the handler itself.
    fn is_callback_context_parameter(&self, param_name: &str) -> bool {
        let lower = param_name.to_lowercase();
        matches!(
            lower.as_str(),
            "userdata"
                | "user_data"
                | "cb_arg"
                | "cb_data"
                | "cb_ctx"
                | "callback_data"
                | "callback_context"
                | "priv"
                | "opaque"
                | "closure"
                | "functor_context"
        )
    }
}
