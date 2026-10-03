// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! ERR33-C: Detect and handle standard library errors
//!
//! A standard library function whose return value signals failure has to
//! have that value checked. Three shapes are examined:
//!
//! 1. A stored result: `p = malloc(n)` or `size_t n = fread(...)`. It counts
//!    as checked when a later expression tests the same object against the
//!    function's own error value (NULL, EOF, a negative value, `(T)-1`, a
//!    short count, `SIG_ERR`, `errno` for `strto*`) before the object is
//!    written again. That is decided by the AST in
//!    `result_checks::stored_result_is_tested`: the operand is resolved by
//!    declaration, not by spelling (ADR-0006); a comparison inside
//!    `assert(...)` does not count (ADR-0010); and `n == 0` does not detect a
//!    negative result. `p = realloc(p, n)` is reported as the leak it is.
//! 2. A call used directly: `if (fopen(...) != NULL)`, a call inside a
//!    condition, a `return`, a comma expression or another call's argument
//!    is consumed. A direct comparison against the wrong value
//!    (`if (fgetc(f) == 0)`) is reported as an incorrect check (CWE-253).
//! 3. A discarded result: a standalone `malloc(n);`. `(void)f()` is an
//!    explicit discard and is not reported. Neither is a discard ERR33-C-EX1
//!    permits, `signal(s, SIG_IGN/SIG_DFL)`, or `time(&t)` with an output
//!    argument.
//!
//! ERR33-C-EX1 is applied as CERT writes it (SEI CERT C Coding Standard,
//! ERR33-C, cmu-sei.github.io/secure-coding-standards, fetched 2026-09-27).
//! Its table of "Functions for which Return Values Need Not Be Checked"
//! names `putchar()`, `putwchar()`, `puts()`, `putws()`, `printf()`,
//! `vprintf()`, `wprintf()` and `vwprintf()` (and functions with no error
//! return: `kill_dependency()` and the `mem*`/`str*` copy and set
//! functions), and then says:
//!
//! > The return value of a call to fprintf() or one of its variants
//! > ( vfprintf() , wfprintf() , vwfprintf() ) or one of the file output
//! > functions fputc() , fputwc() , fputs() , fputws() may be ignored if the
//! > output is being directed to stdout or stderr . Otherwise, the return
//! > value must be checked.
//!
//! So `fprintf(fp, ...)` to a file is reported, and `sprintf`, `vsprintf`,
//! `putc` and `putwc`, which EX1 does not name, are never exempt.
//! `wfprintf`/`vwfprintf` are CERT's spellings of the standard's `fwprintf`/
//! `vfwprintf`; both spellings are accepted. `snprintf`/`vsnprintf` are not
//! in EX1 either, and their result also says whether the output was
//! truncated.
//!
//! `fclose()` gets no exception. ERR33-C-EX1 does not list it, and a failing
//! `fclose()` on a cleanup path is still a failure; the compliant way to
//! discard it is `(void)fclose(fp)`.

use super::super::{CertRule, RuleViolation};
use crate::analyze::check_macros::{self, MacroDefinition};
use crate::analyze::const_eval;
use crate::analyze::context::ProjectContext;
use crate::analyze::context::ScopedTable;
use crate::analyze::context::VisibleTypes;
use crate::analyze::function_summary::FunctionSummary;
use crate::manifest::Severity;
use crate::settings::{AnalysisSettings, IntFacts};
use crate::utility::cert_c::ast_utils::{
    get_identifier_from_declarator, get_node_text, resolve_identifier_declarator,
};
use crate::utility::cert_c::expr_type::TypeEnv;
use crate::utility::cert_c::result_checks;
use lang_parsing_substrate::query;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

/// Error return type categories for CWE-253 incorrect check detection
#[derive(Debug)]
enum ErrorReturnKind {
    /// Returns NULL pointer on error (fgets, fopen, malloc, etc.)
    NullPointer,
    /// Returns negative value on error (fprintf, printf, snprintf)
    NegativeInt,
    /// Returns EOF (-1) on error (putc, fputc, putchar, fputs, puts, scanf, etc.)
    Eof,
    /// Returns non-zero on error (remove, rename, fclose, fseek)
    NonZero,
    /// Returns count, compare against expected (fread, fwrite)
    Count,
}

pub struct Err33C {
    function_summaries: RefCell<ScopedTable<FunctionSummary>>,
    project_aliases: RefCell<Arc<HashMap<String, String>>>,
    /// Every live target of each project alias
    /// (`ProjectContext::macro_alias_alternatives`), for the names an alias
    /// accuses through in some build.
    project_alias_alternatives: RefCell<Arc<HashMap<String, Vec<String>>>>,
    current_aliases: RefCell<HashMap<String, String>>,
    /// Every macro definition and conditionally defined name: the prescan's,
    /// and this file's (set by `check`). A result passed to a function-like
    /// macro is tested when every definition's expansion tests it.
    project_macros: RefCell<(Arc<Definitions>, Arc<HashSet<String>>)>,
    file_macros: RefCell<(Definitions, HashSet<String>)>,
    macro_test_cache: RefCell<result_checks::MacroTestCache>,
    /// The typedefs and struct fields this file sees, for typing the object a
    /// result is stored in.
    visible: RefCell<VisibleTypes>,
    /// The integer data model the settings credit, for typing the object a
    /// result is stored in.
    data_model: Cell<IntFacts>,
}

type Definitions = HashMap<String, Vec<MacroDefinition>>;

impl Err33C {
    pub fn new() -> Self {
        Self {
            function_summaries: RefCell::default(),
            project_aliases: RefCell::new(Arc::new(HashMap::new())),
            project_alias_alternatives: RefCell::new(Arc::new(HashMap::new())),
            current_aliases: RefCell::new(HashMap::new()),
            project_macros: RefCell::default(),
            file_macros: RefCell::default(),
            macro_test_cache: RefCell::default(),
            visible: RefCell::default(),
            data_model: Cell::default(),
        }
    }
}

impl CertRule for Err33C {
    fn set_analysis_settings(&self, settings: &Arc<AnalysisSettings>) {
        self.data_model.set(settings.facts);
    }

    fn rule_id(&self) -> &'static str {
        "ERR33-C"
    }

    fn description(&self) -> &'static str {
        "Detect and handle standard library errors"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "ERR33-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
        *self.project_aliases.borrow_mut() = context.macro_aliases.clone();
        *self.project_macros.borrow_mut() = (
            context.macro_definitions.clone(),
            context.conditional_macro_names.clone(),
        );
        *self.project_alias_alternatives.borrow_mut() = context.macro_alias_alternatives.clone();
    }

    fn set_visible_types(&self, types: &VisibleTypes) {
        *self.visible.borrow_mut() = types.clone();
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        // Merge project-level aliases with per-file aliases (per-file wins)
        let mut aliases =
            const_eval::merged_macro_aliases(&self.project_aliases.borrow(), node, source);
        // An alias defined more than one way reaches the callee this rule
        // looks for if any live definition does (ADR-0010 D1).
        let alternatives = const_eval::merged_macro_alias_alternatives(
            &self.project_alias_alternatives.borrow(),
            node,
            source,
        );
        const_eval::with_accusing_alias_targets(&mut aliases, &alternatives, |t| {
            self.is_error_returning_function(t) || self.get_error_return_kind(t).is_some()
        });
        *self.current_aliases.borrow_mut() = aliases;
        *self.file_macros.borrow_mut() = (
            check_macros::collect_macro_definitions(source),
            check_macros::collect_conditional_macro_names(source),
        );
        self.macro_test_cache.borrow_mut().clear();

        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Err33C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let matches = query::find_descendants_of_kinds(
            *node,
            &[
                "call_expression",
                "expression_statement",
                "assignment_expression",
                "init_declarator",
            ],
        );
        for n in matches {
            match n.kind() {
                "call_expression" => {
                    self.check_function_call(&n, source, violations);
                }
                "expression_statement" => {
                    // Check if this is a standalone function call that ignores return value
                    if let Some(child) = n.child(0) {
                        if child.kind() == "call_expression" {
                            self.check_ignored_return_value(&n, &child, source, violations);
                        }
                    }
                }
                "assignment_expression" => {
                    self.check_assignment(&n, source, violations);
                }
                "init_declarator" => {
                    self.check_init_declarator(&n, source, violations);
                }
                _ => {}
            }
        }
    }

    fn check_function_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Skip standalone calls (direct child of expression_statement) — those are
        // handled by check_ignored_return_value to avoid duplicate violations.
        if let Some(parent) = node.parent() {
            if parent.kind() == "expression_statement" {
                return;
            }
        }

        if let Some(function_node) = node.child_by_field_name("function") {
            let raw_name = get_node_text(&function_node, source);
            let function_name = self.resolve_name(raw_name);

            let in_assignment = self.is_call_in_assignment_or_declaration(node, source);

            // CWE-253: Check for incorrect comparison of return value (direct calls only)
            if !in_assignment {
                if self.check_incorrect_comparison(node, &function_name, source, violations) {
                    return;
                }
            }

            if self.is_error_returning_function(&function_name) {
                // Skip if this call is part of an assignment or declaration
                // Those cases are handled by check_assignment and check_init_declarator
                if in_assignment {
                    return;
                }

                // Check if the return value is properly handled
                if !self.is_return_value_checked(node, source) {
                    let start_point = node.start_position();
                    let call_text = get_node_text(&node, source);

                    let error_info = self.get_error_info(&function_name);

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Return value of '{}' not checked: '{}' - {}",
                            function_name, call_text, error_info.description
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(error_info.suggestion),
                        ..Default::default()
                    });
                }
            }
        }
    }

    fn is_call_in_assignment_or_declaration(&self, call_node: &Node, source: &str) -> bool {
        let mut current = call_node.parent();
        while let Some(parent) = current {
            match parent.kind() {
                // Return value is consumed by assignment, declaration, or as argument to another call
                "assignment_expression" | "init_declarator" | "argument_list" => return true,
                // Ternary: malloc(n) ? ... : ...
                "conditional_expression" => return true,
                // Cast: (int*)malloc(n) or (void)fprintf(...)
                "cast_expression" => {
                    // (void)func() is intentional discard — CERT-C compliant pattern
                    if let Some(type_node) = parent.child_by_field_name("type") {
                        let type_text = get_node_text(&type_node, source);
                        if type_text.trim() == "void" {
                            return true;
                        }
                    }
                    // Keep walking — the cast's parent might be an assignment
                }
                "expression_statement" | "compound_statement" | "function_definition" => break,
                _ => {}
            }
            current = parent.parent();
        }
        false
    }

    fn check_ignored_return_value(
        &self,
        stmt_node: &Node,
        call_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(function_node) = call_node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);

            if self.is_error_returning_function(function_name) {
                // ERR33-C-EX1, exactly as written (see the module doc):
                // console output may be discarded, output to any other
                // stream may not, and sprintf/vsprintf/putc are not in it.
                if ex1_permits_discard(
                    function_name,
                    call_node,
                    source,
                    &self.current_aliases.borrow(),
                ) {
                    return;
                }

                // Suppress signal(SIG*, SIG_IGN/SIG_DFL) — return value
                // (previous handler) is universally ignored in practice.
                if function_name == "signal" {
                    if let Some(args) = call_node.child_by_field_name("arguments") {
                        if let Some(second_arg) = args.child(3) {
                            let arg_text = get_node_text(&second_arg, source);
                            if arg_text == "SIG_IGN" || arg_text == "SIG_DFL" {
                                return;
                            }
                        }
                    }
                }

                // Suppress time(&t) when output parameter is used —
                // result is stored via pointer arg, return value is redundant.
                if function_name == "time" {
                    if let Some(args) = call_node.child_by_field_name("arguments") {
                        if let Some(first_arg) = args.child(1) {
                            let arg_text = get_node_text(&first_arg, source);
                            if arg_text != "NULL" && arg_text != "0" && arg_text != "((void *)0)" {
                                return;
                            }
                        }
                    }
                }

                let start_point = stmt_node.start_position();
                let call_text = get_node_text(&call_node, source);

                let error_info = self.get_error_info(function_name);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Return value of '{}' ignored: '{}' - {}",
                        function_name, call_text, error_info.description
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(error_info.suggestion),
                    ..Default::default()
                });
            }
        }
    }

    fn check_assignment(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            // Skip assignments to dereferenced pointers like *ptr = func()
            // These are output parameters where the caller is responsible for checking the stored value
            if left.kind() == "pointer_expression" {
                return;
            }

            if right.kind() == "call_expression" {
                if let Some(function_node) = right.child_by_field_name("function") {
                    let function_name = get_node_text(&function_node, source);
                    let var_name = get_node_text(&left, source);

                    if self.is_error_returning_function(function_name) {
                        // Special check for dangerous realloc pattern: p = realloc(p, size)
                        if function_name == "realloc"
                            && self.is_dangerous_realloc_pattern(&right, var_name, source)
                        {
                            let start_point = node.start_position();
                            let call_text = get_node_text(&right, source);

                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::High,
                                message: format!(
                                    "Dangerous realloc pattern: '{}' - assigning realloc result to the same pointer it's reallocating. If realloc fails, the original pointer is lost, causing a memory leak.",
                                    call_text
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some("Use a temporary pointer: 'temp = realloc(p, size); if (temp == NULL) { /* handle error */ } p = temp;'".to_string()),
                            ..Default::default()
                            });
                            return; // Don't perform the regular error check
                        }

                        // Tested against the function's error value, in the
                        // assignment's own controlling expression or after it,
                        // before the variable is written again.
                        if !self.stored_result_is_tested(node, &left, &right, function_name, source)
                        {
                            let start_point = node.start_position();
                            let call_text = get_node_text(&right, source);

                            let error_info = self.get_error_info(function_name);

                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::High,
                                message: format!(
                                    "Return value of '{}' assigned to '{}' but not checked for errors: '{}' - {}",
                                    function_name, var_name, call_text, error_info.description
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some(error_info.suggestion),
                            ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    fn check_init_declarator(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Handle pattern: TYPE *var = function_call();
        // Also handle: TYPE *var = (TYPE*)function_call(); (with cast)
        if let Some(declarator) = node.child_by_field_name("declarator") {
            if let Some(value) = node.child_by_field_name("value") {
                // Handle cast_expression wrapping the call
                let call_node = if value.kind() == "cast_expression" {
                    value.child_by_field_name("value")
                } else if value.kind() == "call_expression" {
                    Some(value)
                } else {
                    None
                };

                if let Some(call) = call_node {
                    if call.kind() == "call_expression" {
                        if let Some(function_node) = call.child_by_field_name("function") {
                            let function_name = get_node_text(&function_node, source);

                            // Extract variable name from declarator
                            let var_name = get_identifier_from_declarator(&declarator, source);

                            if self.is_error_returning_function(function_name) {
                                // Check if the declared variable is later tested
                                // against the function's error value.
                                let tested =
                                    Self::declarator_name(&declarator).is_some_and(|name_node| {
                                        self.stored_result_is_tested(
                                            node,
                                            &name_node,
                                            &call,
                                            function_name,
                                            source,
                                        )
                                    });
                                if !tested {
                                    let start_point = node.start_position();
                                    let call_text = get_node_text(&value, source);

                                    let error_info = self.get_error_info(function_name);

                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        severity: Severity::High,
                                        message: format!(
                                            "Return value of '{}' assigned to '{}' but not checked for errors: '{}' - {}",
                                            function_name, var_name, call_text, error_info.description
                                        ),
                                        file_path: String::new(),
                                        line: start_point.row + 1,
                                        column: start_point.column + 1,
                                        suggestion: Some(error_info.suggestion),
                                    ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check if a function name matches a common wrapper/safe-allocation pattern.
    /// These wrappers typically check errors internally (abort/exit on failure).
    fn is_safe_wrapper_function(&self, function_name: &str) -> bool {
        // Check function summaries: if the function never returns, it handles errors
        // internally (e.g., calls abort/exit on failure).
        let summaries = self.function_summaries.borrow();
        if let Some(summary) = summaries.get(function_name) {
            if summary.never_returns {
                return true;
            }
        }

        // Common wrapper prefixes that handle errors internally
        let safe_prefixes = [
            "x", "safe_", "checked_", "my_", "g_", "g_try_", "php_", "ap_", "pr_",
        ];
        let safe_suffixes = ["_or_die", "_or_abort", "_nofail", "_safe"];

        for prefix in &safe_prefixes {
            if let Some(rest) = function_name.strip_prefix(prefix) {
                // Verify the rest is a known error-returning function
                if self.is_base_error_returning_function(rest) {
                    return true;
                }
            }
        }

        for suffix in &safe_suffixes {
            if function_name.ends_with(suffix) {
                return true;
            }
        }

        false
    }

    /// Check if the base function name (without wrapper prefix) is error-returning.
    fn is_base_error_returning_function(&self, name: &str) -> bool {
        matches!(
            name,
            "malloc"
                | "calloc"
                | "realloc"
                | "alloc"
                | "fopen"
                | "fgets"
                | "fread"
                | "fwrite"
                | "strdup"
                | "strndup"
                | "open"
                | "close"
                | "read"
                | "write"
        )
    }

    fn is_error_returning_function(&self, function_name: &str) -> bool {
        // Skip known safe wrapper functions
        if self.is_safe_wrapper_function(function_name) {
            return false;
        }

        cert_error_return(function_name).is_some()
            || matches!(
                function_name,
                // Outside CERT's table, but each signals failure through its
                // result: the non-`_s` time conversions and `gets` return
                // NULL, `system`/`putenv`/`setenv` a status, and the
                // duplication functions NULL.
                "asctime" | "ctime" | "gets" | "system" | "putenv" | "setenv" | "strdup"
                    | "strndup"
                    // In ERR33-C-EX1's table rather than the main one; a
                    // discard is exempt (`ex1_permits_discard`), a stored
                    // result is still held to its test.
                    | "printf" | "vprintf"
            )
        // Math functions covered by FLP32-C are not listed, to avoid
        // double-flagging. Recorded in this rule's TOML as `[references]
        // related = [..., "FLP32-C"]` (cross-rule overlap policy:
        // docs/design/cross-rule-overlap.md). This is a `related` tag, not a
        // validated `defers_to` exception -- an earlier fix found zero
        // ground-truth-labeled co-located data for this pair. If math
        // functions are ever added, it is a detection-behavior change and
        // needs delta-adjudication before any precision claim.
    }

    fn get_error_info(&self, function_name: &str) -> ErrorInfo {
        let functions_info = self.get_function_error_info();
        functions_info
            .get(function_name)
            .cloned()
            .unwrap_or_else(|| match cert_error_return(function_name) {
                Some(error) => ErrorInfo {
                    description: format!("error return (CERT ERR33-C table): {}", error),
                    suggestion: format!(
                        "Test the result for its error return ({}) before relying on it",
                        error
                    ),
                },
                None => ErrorInfo {
                    description: "Can return error indicator".to_string(),
                    suggestion: "Check return value for errors".to_string(),
                },
            })
    }

    fn get_function_error_info(&self) -> HashMap<&'static str, ErrorInfo> {
        let mut info = HashMap::new();

        // Memory management
        info.insert(
            "malloc",
            ErrorInfo {
                description: "Returns NULL on allocation failure".to_string(),
                suggestion: "Check if (ptr == NULL) before using the allocated memory".to_string(),
            },
        );
        info.insert(
            "calloc",
            ErrorInfo {
                description: "Returns NULL on allocation failure".to_string(),
                suggestion: "Check if (ptr == NULL) before using the allocated memory".to_string(),
            },
        );
        info.insert("realloc", ErrorInfo {
            description: "Returns NULL on reallocation failure".to_string(),
            suggestion: "Use temporary pointer: new_ptr = realloc(ptr, size); if (new_ptr == NULL) handle_error();".to_string(),
        });

        // File I/O
        info.insert(
            "fopen",
            ErrorInfo {
                description: "Returns NULL if file cannot be opened".to_string(),
                suggestion: "Check if (file == NULL) before using the file pointer".to_string(),
            },
        );
        info.insert(
            "fseek",
            ErrorInfo {
                description: "Returns non-zero on failure".to_string(),
                suggestion: "Check if (fseek(file, offset, whence) != 0) for seek errors"
                    .to_string(),
            },
        );
        info.insert(
            "ftell",
            ErrorInfo {
                description: "Returns -1L on failure".to_string(),
                suggestion: "Check if (pos == -1L) for position errors".to_string(),
            },
        );
        info.insert(
            "fread",
            ErrorInfo {
                description: "Returns number of items read, may be less than requested".to_string(),
                suggestion: "Check if (items_read == expected_items) or handle partial reads"
                    .to_string(),
            },
        );
        info.insert(
            "fwrite",
            ErrorInfo {
                description: "Returns number of items written, may be less than requested"
                    .to_string(),
                suggestion: "Check if (items_written == expected_items) for write errors"
                    .to_string(),
            },
        );
        info.insert(
            "fgets",
            ErrorInfo {
                description: "Returns NULL on error or EOF".to_string(),
                suggestion: "Check if (fgets(buffer, size, file) != NULL) before using buffer"
                    .to_string(),
            },
        );
        info.insert(
            "fclose",
            ErrorInfo {
                description: "Returns non-zero on error".to_string(),
                suggestion: "Check if (fclose(file) != 0) for close errors".to_string(),
            },
        );
        info.insert(
            "fputs",
            ErrorInfo {
                description: "Returns EOF on error".to_string(),
                suggestion: "Check if (fputs(str, file) == EOF) for write errors".to_string(),
            },
        );
        info.insert(
            "fgetc",
            ErrorInfo {
                description: "Returns EOF on error or end of file".to_string(),
                suggestion: "Check if (c = fgetc(file)) != EOF and distinguish from actual EOF"
                    .to_string(),
            },
        );
        info.insert(
            "fputc",
            ErrorInfo {
                description: "Returns EOF on error".to_string(),
                suggestion: "Check if (fputc(c, file) == EOF) for write errors".to_string(),
            },
        );

        // String/locale functions
        info.insert(
            "setlocale",
            ErrorInfo {
                description: "Returns NULL if locale cannot be set".to_string(),
                suggestion: "Check if (setlocale(category, locale) == NULL) for locale errors"
                    .to_string(),
            },
        );
        info.insert("strtol", ErrorInfo {
            description: "Sets errno on overflow/underflow, uses endptr for parsing errors".to_string(),
            suggestion: "Check errno and endptr: errno = 0; val = strtol(str, &endptr, base); if (errno != 0 || endptr == str) handle_error();".to_string(),
        });

        // Environment functions
        info.insert(
            "getenv",
            ErrorInfo {
                description: "Returns NULL if environment variable not found".to_string(),
                suggestion: "Check if (result == NULL) before using the returned string"
                    .to_string(),
            },
        );

        // Formatted I/O
        info.insert(
            "printf",
            ErrorInfo {
                description: "Returns negative value on output error".to_string(),
                suggestion: "Check if (printf(...) < 0) for output errors".to_string(),
            },
        );
        info.insert("snprintf", ErrorInfo {
            description: "Returns negative on error, or >= buffer size on truncation".to_string(),
            suggestion: "Check result: int ret = snprintf(buf, size, fmt, ...); if (ret < 0 || ret >= size) handle_error();".to_string(),
        });

        // Time functions
        info.insert(
            "time",
            ErrorInfo {
                description: "Returns (time_t)(-1) on failure".to_string(),
                suggestion: "Check if (result == (time_t)(-1)) for time errors".to_string(),
            },
        );
        info.insert(
            "ctime",
            ErrorInfo {
                description: "Returns NULL on error".to_string(),
                suggestion: "Check if (result == NULL) before using time string".to_string(),
            },
        );
        info.insert(
            "localtime",
            ErrorInfo {
                description: "Returns NULL on error".to_string(),
                suggestion: "Check if (result == NULL) before using time structure".to_string(),
            },
        );
        info.insert(
            "gmtime",
            ErrorInfo {
                description: "Returns NULL on error".to_string(),
                suggestion: "Check if (result == NULL) before using time structure".to_string(),
            },
        );
        info.insert(
            "asctime",
            ErrorInfo {
                description: "Returns NULL on error".to_string(),
                suggestion: "Check if (result == NULL) before using time string".to_string(),
            },
        );

        // File operations
        info.insert(
            "remove",
            ErrorInfo {
                description: "Returns non-zero on failure".to_string(),
                suggestion: "Check if (remove(filename) != 0) for deletion errors".to_string(),
            },
        );
        info.insert(
            "rename",
            ErrorInfo {
                description: "Returns non-zero on failure".to_string(),
                suggestion: "Check if (rename(oldname, newname) != 0) for rename errors"
                    .to_string(),
            },
        );

        // System functions
        info.insert(
            "system",
            ErrorInfo {
                description: "Returns -1 on failure to execute command".to_string(),
                suggestion: "Check if (system(command) == -1) for execution errors".to_string(),
            },
        );

        info
    }

    fn is_return_value_checked(&self, node: &Node, source: &str) -> bool {
        // Check if this function call is part of a condition or assignment
        if let Some(parent) = node.parent() {
            match parent.kind() {
                // Used in a condition
                "if_statement"
                | "while_statement"
                | "for_statement"
                | "conditional_expression"
                | "binary_expression"
                | "unary_expression"
                | "parenthesized_expression" => {
                    return true;
                }
                // Used in return statement
                "return_statement" => {
                    return true;
                }
                // Cast expression wrapping the call — check the cast's parent
                "cast_expression" => {
                    return self.is_return_value_checked(&parent, source);
                }
                // Comma expression — return value used in some context
                "comma_expression" => {
                    return true;
                }
                _ => {}
            }
        }

        // Check for compound condition pattern: if (!(f = fopen(...)))
        // Walk up through parenthesized/unary/assignment to find if-statement ancestor
        if self.is_in_compound_condition_check(node) {
            return true;
        }

        false
    }

    /// Check if a call is inside a compound condition like `if (!(ptr = malloc(n)))` or
    /// `if ((f = fopen(...)) == NULL)`.
    fn is_in_compound_condition_check(&self, node: &Node) -> bool {
        let mut current = node.parent();
        let mut depth = 0;
        while let Some(parent) = current {
            if depth > 6 {
                break;
            }
            match parent.kind() {
                "if_statement" | "while_statement" | "for_statement" => return true,
                "conditional_expression" => return true,
                "assignment_expression"
                | "parenthesized_expression"
                | "unary_expression"
                | "binary_expression"
                | "cast_expression" => {
                    // Keep walking up
                }
                "expression_statement" | "compound_statement" | "function_definition" => {
                    break;
                }
                _ => {}
            }
            current = parent.parent();
            depth += 1;
        }
        false
    }

    /// Whether the result of `call`, stored by `store` into `target`, is
    /// tested against `function_name`'s error value before `target` is
    /// written again -- see `result_checks::stored_result_is_tested`. A
    /// function the error-signal table does not know is held to any test of
    /// its result.
    fn stored_result_is_tested(
        &self,
        store: &Node,
        target: &Node,
        call: &Node,
        function_name: &str,
        source: &str,
    ) -> bool {
        let signal = result_checks::error_signal_for(function_name)
            .unwrap_or(result_checks::ErrorSignal::Any);
        let project = self.project_macros.borrow();
        let file = self.file_macros.borrow();
        let macros = result_checks::MacroView {
            defs: [&project.0, &file.0],
            conditional: [&project.1, &file.1],
            cache: &self.macro_test_cache,
        };
        let visible = self.visible.borrow();
        let types = TypeEnv::visible(&visible, self.data_model.get());
        result_checks::stored_result_is_tested(store, target, call, signal, source, &macros, &types)
    }

    /// The identifier a declarator declares (`*p`, `p[4]`, `(*p)` -> `p`).
    fn declarator_name<'a>(declarator: &Node<'a>) -> Option<Node<'a>> {
        let mut n = *declarator;
        loop {
            if n.kind() == "identifier" {
                return Some(n);
            }
            n = n
                .child_by_field_name("declarator")
                .or_else(|| n.named_child(0))?;
        }
    }

    /// Check for the dangerous realloc pattern where the same variable is both the argument and the assignment target.
    /// Pattern: p = realloc(p, size) - if realloc fails and returns NULL, the original pointer p is lost.
    fn is_dangerous_realloc_pattern(
        &self,
        call_node: &Node,
        assigned_var: &str,
        source: &str,
    ) -> bool {
        // Get the arguments to realloc
        if let Some(arguments) = call_node.child_by_field_name("arguments") {
            // realloc takes (ptr, size), we need to check if the first argument is the same as assigned_var
            for i in 0..arguments.child_count() {
                if let Some(arg) = arguments.child(i) {
                    if arg.kind() == "identifier" {
                        let arg_text = get_node_text(&arg, source);
                        // If the first argument to realloc is the same variable being assigned to, it's dangerous
                        if arg_text == assigned_var {
                            return true;
                        }
                        // Only check the first argument (the pointer being reallocated)
                        break;
                    }
                }
            }
        }
        false
    }

    // ========================================================================
    // CWE-253: Incorrect check of function return value
    // ========================================================================

    /// Resolve a function name through macro aliases.
    fn resolve_name(&self, name: &str) -> String {
        let aliases = self.current_aliases.borrow();
        if let Some(target) = aliases.get(name) {
            target.clone()
        } else {
            name.to_string()
        }
    }

    /// Get the error return kind for a function, used for CWE-253 validation.
    /// This covers more functions than is_error_returning_function() to detect
    /// incorrect comparisons on wchar_t variants and other stdlib functions.
    fn get_error_return_kind(&self, function_name: &str) -> Option<ErrorReturnKind> {
        match function_name {
            // NULL pointer returns
            "fgets" | "fgetws" | "fopen" | "freopen" | "tmpfile" | "tmpnam" | "malloc"
            | "calloc" | "realloc" | "aligned_alloc" | "getenv" | "setlocale" | "ctime"
            | "localtime" | "gmtime" | "asctime" | "strdup" | "strndup" => {
                Some(ErrorReturnKind::NullPointer)
            }

            // Negative int on error (return count or negative)
            "fprintf" | "printf" | "sprintf" | "snprintf" | "vfprintf" | "vprintf" | "vsprintf"
            | "vsnprintf" | "fwprintf" | "wprintf" | "swprintf" => {
                Some(ErrorReturnKind::NegativeInt)
            }

            // EOF on error
            "putc" | "fputc" | "putchar" | "putwc" | "fputwc" | "putwchar" | "fputs" | "fputws"
            | "puts" | "ungetc" | "ungetwc" | "fgetc" | "fgetwc" | "scanf" | "fscanf"
            | "sscanf" | "wscanf" | "fwscanf" | "swscanf" => Some(ErrorReturnKind::Eof),

            // Non-zero on error
            "remove" | "rename" | "fclose" | "fseek" | "fflush" | "fsetpos" | "atexit"
            | "raise" => Some(ErrorReturnKind::NonZero),

            // Count return (compare against expected)
            "fread" | "fwrite" | "mbstowcs" | "wcstombs" | "strftime" | "wcsftime" => {
                Some(ErrorReturnKind::Count)
            }

            _ => None,
        }
    }

    /// Check if a function call has an incorrect comparison for its return value (CWE-253).
    /// Returns true if an incorrect comparison was found and a violation was emitted.
    fn check_incorrect_comparison(
        &self,
        call_node: &Node,
        function_name: &str,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) -> bool {
        let error_kind = match self.get_error_return_kind(function_name) {
            Some(k) => k,
            None => return false,
        };

        // Walk up to find the binary_expression containing this call
        let mut current = call_node.parent();
        let mut depth = 0;
        while let Some(parent) = current {
            if depth > 3 {
                break;
            }

            if parent.kind() == "binary_expression" {
                return self.validate_comparison_for_function(
                    &parent,
                    call_node,
                    function_name,
                    &error_kind,
                    source,
                    violations,
                );
            }

            // Keep walking through parenthesized and cast expressions
            if parent.kind() == "parenthesized_expression" || parent.kind() == "cast_expression" {
                current = parent.parent();
                depth += 1;
                continue;
            }

            break;
        }

        false
    }

    /// Validate whether a binary comparison is correct for the given function's error semantics.
    /// Returns true if an incorrect comparison was found and a violation was emitted.
    fn validate_comparison_for_function(
        &self,
        binary_expr: &Node,
        call_node: &Node,
        function_name: &str,
        error_kind: &ErrorReturnKind,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) -> bool {
        let operator = match binary_expr.child_by_field_name("operator") {
            Some(op) => get_node_text(&op, source),
            None => return false,
        };
        let op = operator.trim();

        let (left, right) = match (
            binary_expr.child_by_field_name("left"),
            binary_expr.child_by_field_name("right"),
        ) {
            (Some(l), Some(r)) => (l, r),
            _ => return false,
        };

        // Figure out the comparison value (the side that ISN'T the call)
        let cmp_value = if self.node_byte_range_contains(&left, call_node) {
            get_node_text(&right, source)
        } else if self.node_byte_range_contains(&right, call_node) {
            get_node_text(&left, source)
        } else {
            return false;
        };
        let cmp_value = cmp_value.trim();

        let is_incorrect = match error_kind {
            ErrorReturnKind::NullPointer => {
                // Pointer functions: ordered comparisons (<, >, <=, >=) are always wrong
                matches!(op, "<" | ">" | "<=" | ">=")
            }
            ErrorReturnKind::NegativeInt => {
                // Error is < 0. Checking == 0 doesn't detect errors.
                op == "==" && cmp_value == "0"
            }
            ErrorReturnKind::Eof => {
                // Error is EOF (-1). Checking == 0 doesn't detect errors.
                op == "==" && cmp_value == "0"
            }
            ErrorReturnKind::NonZero => {
                // Error is non-zero, 0 means success. Both `== 0` (success path)
                // and `!= 0` (error path) are valid error-handling patterns.
                false
            }
            ErrorReturnKind::Count => {
                // Return is count (size_t). Checking < 0 on unsigned is always false.
                // `== 0` is a valid check for "nothing processed".
                op == "<" && cmp_value == "0"
            }
        };

        if is_incorrect {
            let suggestion =
                self.get_incorrect_check_suggestion(function_name, error_kind, op, cmp_value);

            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Incorrect check of '{}' return value: '{} {}' does not properly \
                     detect the error condition. {}",
                    function_name, op, cmp_value, suggestion
                ),
                file_path: String::new(),
                line: call_node.start_position().row + 1,
                column: call_node.start_position().column + 1,
                suggestion: Some(suggestion),
                ..Default::default()
            });
            return true;
        }

        false
    }

    /// Generate a suggestion message for an incorrect return value check.
    fn get_incorrect_check_suggestion(
        &self,
        function_name: &str,
        error_kind: &ErrorReturnKind,
        op: &str,
        cmp_value: &str,
    ) -> String {
        match error_kind {
            ErrorReturnKind::NullPointer => {
                format!(
                    "{}() returns a pointer that is NULL on error. \
                     Use '== NULL' or '!= NULL' instead of '{} {}'",
                    function_name, op, cmp_value
                )
            }
            ErrorReturnKind::NegativeInt => {
                format!(
                    "{}() returns a negative value on error. \
                     Use '< 0' to detect errors instead of '{} {}'",
                    function_name, op, cmp_value
                )
            }
            ErrorReturnKind::Eof => {
                format!(
                    "{}() returns EOF (-1) on error. \
                     Use '== EOF' to detect errors instead of '{} {}'",
                    function_name, op, cmp_value
                )
            }
            ErrorReturnKind::NonZero => {
                format!(
                    "{}() returns non-zero on error. \
                     Use '!= 0' to detect errors instead of '{} {}'",
                    function_name, op, cmp_value
                )
            }
            ErrorReturnKind::Count => {
                format!(
                    "{}() returns the number of items processed. \
                     Compare against expected count instead of '{} {}'",
                    function_name, op, cmp_value
                )
            }
        }
    }

    /// Check if a node's byte range contains another node
    fn node_byte_range_contains(&self, potential_parent: &Node, child: &Node) -> bool {
        potential_parent.start_byte() <= child.start_byte()
            && potential_parent.end_byte() >= child.end_byte()
    }
}

#[derive(Debug, Clone)]
struct ErrorInfo {
    description: String,
    suggestion: String,
}

/// ERR33-C's table of standard library functions and the value each returns
/// on error, as CERT writes it (SEI CERT C Coding Standard, ERR33-C, "Table
/// of Standard Library Functions", wiki.sei.cmu.edu, fetched 2026-09-28).
/// Footnote markers are dropped. `puts`, `putchar`, `putwchar`, `putws`,
/// `printf`, `vprintf`, `wprintf` and `vwprintf` are not here: CERT lists
/// them in ERR33-C-EX1's table of functions whose results need not be
/// checked.
const CERT_ERROR_RETURNS: &[(&str, &str)] = &[
    ("aligned_alloc", "NULL"),
    ("asctime_s", "Nonzero"),
    ("at_quick_exit", "Nonzero"),
    ("atexit", "Nonzero"),
    ("bsearch", "NULL"),
    ("bsearch_s", "NULL"),
    ("btowc", "WEOF"),
    ("c16rtomb", "(size_t)(-1)"),
    ("c32rtomb", "(size_t)(-1)"),
    ("calloc", "NULL"),
    ("clock", "(clock_t)(-1)"),
    ("cnd_broadcast", "thrd_error"),
    ("cnd_init", "thrd_nomem or thrd_error"),
    ("cnd_signal", "thrd_error"),
    ("cnd_timedwait", "thrd_timedout or thrd_error"),
    ("cnd_wait", "thrd_error"),
    ("ctime_s", "Nonzero"),
    ("fclose", "EOF (negative)"),
    ("fflush", "EOF (negative)"),
    ("fgetc", "EOF"),
    ("fgetpos", "Nonzero, errno > 0"),
    ("fgets", "NULL"),
    ("fgetwc", "WEOF"),
    ("fopen", "NULL"),
    ("fopen_s", "Nonzero"),
    ("fprintf", "Negative"),
    ("fprintf_s", "Negative"),
    ("fputc", "EOF"),
    ("fputs", "EOF (negative)"),
    ("fputwc", "WEOF"),
    ("fputws", "EOF (negative)"),
    ("fread", "Elements read"),
    ("freopen", "NULL"),
    ("freopen_s", "Nonzero"),
    ("fscanf", "EOF (negative)"),
    ("fscanf_s", "EOF (negative)"),
    ("fseek", "Nonzero"),
    ("fsetpos", "Nonzero, errno > 0"),
    ("ftell", "-1L, errno > 0"),
    ("fwprintf", "Negative"),
    ("fwprintf_s", "Negative"),
    ("fwrite", "Elements written"),
    ("fwscanf", "EOF (negative)"),
    ("fwscanf_s", "EOF (negative)"),
    ("getc", "EOF"),
    ("getchar", "EOF"),
    ("getenv", "NULL"),
    ("getenv_s", "NULL"),
    ("gets_s", "NULL"),
    ("getwc", "WEOF"),
    ("getwchar", "WEOF"),
    ("gmtime", "NULL"),
    ("gmtime_s", "NULL"),
    ("localtime", "NULL"),
    ("localtime_s", "NULL"),
    ("malloc", "NULL"),
    ("mblen", "-1"),
    ("mbrlen", "(size_t)(-1)"),
    ("mbrtoc16", "(size_t)(-1), errno == EILSEQ"),
    ("mbrtoc32", "(size_t)(-1), errno == EILSEQ"),
    ("mbrtowc", "(size_t)(-1), errno == EILSEQ"),
    ("mbsrtowcs", "(size_t)(-1), errno == EILSEQ"),
    ("mbsrtowcs_s", "Nonzero"),
    ("mbstowcs", "(size_t)(-1)"),
    ("mbstowcs_s", "Nonzero"),
    ("mbtowc", "-1"),
    ("memchr", "NULL"),
    ("mktime", "(time_t)(-1)"),
    ("mtx_init", "thrd_error"),
    ("mtx_lock", "thrd_error"),
    ("mtx_timedlock", "thrd_timedout or thrd_error"),
    ("mtx_trylock", "thrd_busy or thrd_error"),
    ("mtx_unlock", "thrd_error"),
    ("printf_s", "Negative"),
    ("putc", "EOF"),
    ("putwc", "WEOF"),
    ("raise", "Nonzero"),
    ("realloc", "NULL"),
    ("remove", "Nonzero"),
    ("rename", "Nonzero"),
    ("setlocale", "NULL"),
    ("setvbuf", "Nonzero"),
    ("scanf", "EOF (negative)"),
    ("scanf_s", "EOF (negative)"),
    ("signal", "SIG_ERR, errno > 0"),
    ("snprintf", "Negative"),
    ("snprintf_s", "Negative"),
    ("sprintf", "Negative"),
    ("sprintf_s", "Negative"),
    ("sscanf", "EOF (negative)"),
    ("sscanf_s", "EOF (negative)"),
    ("strchr", "NULL"),
    ("strerror_s", "Nonzero"),
    ("strftime", "0"),
    ("strpbrk", "NULL"),
    ("strrchr", "NULL"),
    ("strstr", "NULL"),
    ("strtod", "0, errno == ERANGE"),
    ("strtof", "0, errno == ERANGE"),
    ("strtoimax", "INTMAX_MAX or INTMAX_MIN, errno == ERANGE"),
    ("strtok", "NULL"),
    ("strtok_s", "NULL"),
    ("strtol", "LONG_MAX or LONG_MIN, errno == ERANGE"),
    ("strtold", "0, errno == ERANGE"),
    ("strtoll", "LLONG_MAX or LLONG_MIN, errno == ERANGE"),
    ("strtoumax", "UINTMAX_MAX, errno == ERANGE"),
    ("strtoul", "ULONG_MAX, errno == ERANGE"),
    ("strtoull", "ULLONG_MAX, errno == ERANGE"),
    ("strxfrm", ">= n"),
    ("swprintf", "Negative"),
    ("swprintf_s", "Negative"),
    ("swscanf", "EOF (negative)"),
    ("swscanf_s", "EOF (negative)"),
    ("thrd_create", "thrd_nomem or thrd_error"),
    ("thrd_detach", "thrd_error"),
    ("thrd_join", "thrd_error"),
    ("thrd_sleep", "Negative"),
    ("time", "(time_t)(-1)"),
    ("timespec_get", "0"),
    ("tmpfile", "NULL"),
    ("tmpfile_s", "Nonzero"),
    ("tmpnam", "NULL"),
    ("tmpnam_s", "Nonzero"),
    ("tss_create", "thrd_error"),
    ("tss_get", "0"),
    ("tss_set", "thrd_error"),
    ("ungetc", "EOF"),
    ("ungetwc", "WEOF"),
    ("vfprintf", "Negative"),
    ("vfprintf_s", "Negative"),
    ("vfscanf", "EOF (negative)"),
    ("vfscanf_s", "EOF (negative)"),
    ("vfwprintf", "Negative"),
    ("vfwprintf_s", "Negative"),
    ("vfwscanf", "EOF (negative)"),
    ("vfwscanf_s", "EOF (negative)"),
    ("vprintf_s", "Negative"),
    ("vscanf", "EOF (negative)"),
    ("vscanf_s", "EOF (negative)"),
    ("vsnprintf", "Negative"),
    ("vsnprintf_s", "Negative"),
    ("vsprintf", "Negative"),
    ("vsprintf_s", "Negative"),
    ("vsscanf", "EOF (negative)"),
    ("vsscanf_s", "EOF (negative)"),
    ("vswprintf", "Negative"),
    ("vswprintf_s", "Negative"),
    ("vswscanf", "EOF (negative)"),
    ("vswscanf_s", "EOF (negative)"),
    ("vwprintf_s", "Negative"),
    ("vwscanf", "EOF (negative)"),
    ("vwscanf_s", "EOF (negative)"),
    ("wcrtomb", "(size_t)(-1)"),
    ("wcschr", "NULL"),
    ("wcsftime", "0"),
    ("wcspbrk", "NULL"),
    ("wcsrchr", "NULL"),
    ("wcsrtombs", "(size_t)(-1), errno == EILSEQ"),
    ("wcsrtombs_s", "Nonzero"),
    ("wcsstr", "NULL"),
    ("wcstod", "0, errno == ERANGE"),
    ("wcstof", "0, errno == ERANGE"),
    ("wcstoimax", "INTMAX_MAX or INTMAX_MIN, errno == ERANGE"),
    ("wcstok", "NULL"),
    ("wcstok_s", "NULL"),
    ("wcstol", "LONG_MAX or LONG_MIN, errno == ERANGE"),
    ("wcstold", "0, errno == ERANGE"),
    ("wcstoll", "LLONG_MAX or LLONG_MIN, errno == ERANGE"),
    ("wcstombs", "(size_t)(-1)"),
    ("wcstombs_s", "Nonzero"),
    ("wcstoumax", "UINTMAX_MAX, errno == ERANGE"),
    ("wcstoul", "ULONG_MAX, errno == ERANGE"),
    ("wcstoull", "ULLONG_MAX, errno == ERANGE"),
    ("wcsxfrm", ">= n"),
    ("wctob", "EOF"),
    ("wctomb", "-1"),
    ("wctomb_s", "-1"),
    ("wctrans", "0"),
    ("wctype", "0"),
    ("wmemchr", "NULL"),
    ("wprintf_s", "Negative"),
    ("wscanf", "EOF (negative)"),
    ("wscanf_s", "EOF (negative)"),
];

/// The error return CERT's ERR33-C table gives for `function_name`.
fn cert_error_return(function_name: &str) -> Option<&'static str> {
    CERT_ERROR_RETURNS
        .iter()
        .find(|(name, _)| *name == function_name)
        .map(|(_, error)| *error)
}

/// Whether ERR33-C-EX1 lets a call to `function_name` have its result
/// discarded: always for the console functions in its table, and for the
/// `fprintf` and file-output families only when the stream argument is
/// `stdout` or `stderr`. The stream is named directly or through an
/// object-like alias (`#define MSG_OUT stderr`, from `aliases`), and is
/// neither a local nor a parameter of that name (ADR-0006). A stream held in
/// a variable is not followed: it may be a file, so the discard is reported.
///
/// `puts`, `putchar`, `putws`, `putwchar`, `wprintf` and `vwprintf` are not
/// in CERT's main table, so `is_error_returning_function` never lists them
/// and this is not reached for them; their arm states EX1 for completeness.
fn ex1_permits_discard(
    function_name: &str,
    call_node: &Node,
    source: &str,
    aliases: &HashMap<String, String>,
) -> bool {
    // Index of the stream among the call's arguments, for the functions EX1
    // exempts only when writing to the console.
    let stream_index = match function_name {
        "putchar" | "putwchar" | "puts" | "putws" | "printf" | "vprintf" | "wprintf"
        | "vwprintf" => return true,
        "fprintf" | "vfprintf" | "fwprintf" | "vfwprintf" | "wfprintf" | "vwfprintf" => 0,
        "fputc" | "fputwc" | "fputs" | "fputws" => 1,
        _ => return false,
    };
    let Some(args) = call_node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    let Some(mut stream) = args
        .named_children(&mut cursor)
        .filter(|a| a.kind() != "comment")
        .nth(stream_index)
    else {
        return false;
    };
    while stream.kind() == "parenthesized_expression" {
        match stream.named_child(0) {
            Some(inner) => stream = inner,
            None => return false,
        }
    }
    if stream.kind() != "identifier" {
        return false;
    }
    let name = get_node_text(&stream, source);
    matches!(
        const_eval::resolve_macro_alias(aliases, name),
        "stdout" | "stderr"
    ) && binds_no_local_object(&stream, name, source)
}

/// Whether `ident` is not bound by a local or parameter declaration: it
/// resolves to nothing in the file, or to a file-scope `extern` declaration
/// such as `<stdio.h>`'s own `extern FILE *stderr;`.
fn binds_no_local_object(ident: &Node, name: &str, source: &str) -> bool {
    match resolve_identifier_declarator(ident, name, source) {
        None => true,
        Some((decl, _)) => {
            let mut cursor = decl.walk();
            let is_extern = decl.children(&mut cursor).any(|c| {
                c.kind() == "storage_class_specifier" && get_node_text(&c, source) == "extern"
            });
            is_extern
                && decl
                    .parent()
                    .is_some_and(|p| p.kind() == "translation_unit")
        }
    }
}
