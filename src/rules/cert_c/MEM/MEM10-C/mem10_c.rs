//! MEM10-C: Define and use a pointer validation function
//!
//! Dereferencing invalid pointers leads to undefined behavior. Functions that accept
//! pointer arguments should validate them using a dedicated validation function rather
//! than performing ad-hoc NULL checks. While NULL checking is necessary, it's insufficient
//! to catch all invalid pointers. A centralized validation function provides:
//! 1. Consistent validation logic across the codebase
//! 2. A single point for platform-specific validation enhancements
//! 3. Better maintainability and testability
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! void incr(int *intptr) {
//!     if (intptr == NULL) {  // Direct NULL check
//!         /* Handle error */
//!     }
//!     (*intptr)++;
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! int valid(void *ptr) {
//!     return (ptr != NULL);  // Centralized validation
//! }
//!
//! void incr(int *intptr) {
//!     if (!valid(intptr)) {  // Use validation function
//!         /* Handle error */
//!     }
//!     (*intptr)++;
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Mem10C;

impl CertRule for Mem10C {
    fn rule_id(&self) -> &'static str {
        "MEM10-C"
    }

    fn description(&self) -> &'static str {
        "Define and use a pointer validation function"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "MEM10-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_pointer_validation(node, source, &mut violations);
        self.check_sizeof_pointer_misuse(node, source, &mut violations);
        violations
    }
}

impl Mem10C {
    /// Collect the pointer parameter names of the enclosing function definition.
    /// Returns an empty set if we can't find a function definition ancestor.
    fn collect_enclosing_params<'a>(
        &self,
        node: &Node<'a>,
        source: &str,
    ) -> std::collections::HashSet<String> {
        let mut current = node.parent();
        while let Some(p) = current {
            if p.kind() == "function_definition" {
                return self.extract_pointer_param_names(&p, source);
            }
            current = p.parent();
        }
        std::collections::HashSet::new()
    }

    fn extract_pointer_param_names(
        &self,
        func_node: &Node,
        source: &str,
    ) -> std::collections::HashSet<String> {
        let mut names = std::collections::HashSet::new();
        for i in 0..func_node.child_count() {
            if let Some(child) = func_node.child(i) {
                self.collect_params_from_declarator(&child, source, &mut names);
            }
        }
        names
    }

    fn collect_params_from_declarator(
        &self,
        node: &Node,
        source: &str,
        names: &mut std::collections::HashSet<String>,
    ) {
        if node.kind() == "function_declarator" {
            if let Some(params) = node.child_by_field_name("parameters") {
                for i in 0..params.child_count() {
                    if let Some(param) = params.child(i) {
                        if param.kind() == "parameter_declaration" {
                            if let Some(decl) = param.child_by_field_name("declarator") {
                                let text = get_node_text(&decl, source);
                                // Extract the identifier from declarators like *data, data[], etc.
                                if decl.kind() == "pointer_declarator"
                                    || decl.kind() == "array_declarator"
                                {
                                    if let Some(id) = find_identifier_in_node(&decl, source) {
                                        names.insert(id);
                                    }
                                } else if decl.kind() == "identifier" {
                                    names.insert(text.to_string());
                                }
                            }
                        }
                    }
                }
            }
        } else {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    self.collect_params_from_declarator(&child, source, names);
                }
            }
        }
    }

    fn check_pointer_validation(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // MEM10-C's actual concern (per CERT) is centralizing ad hoc, duplicated,
        // or inconsistent pointer-validity checks into a shared validation
        // function — not flagging every instance of the single, universally
        // accepted early-return NULL-guard idiom (`if (ptr == NULL) return;`).
        // A lone guard in a file is not evidence of duplication or
        // inconsistency, so we gather every candidate ad hoc check across the
        // whole translation unit first and only report them when there is
        // actual evidence that a shared validator is warranted: either (a)
        // the same ad hoc check idiom is repeated at multiple sites in the
        // file, or (b) the file already defines a dedicated validation
        // function elsewhere yet this site still does an ad hoc check instead
        // of calling it (a genuine inconsistency).
        let has_existing_validator = file_defines_validator_function(node, source);

        let mut candidates: Vec<(Node, Node)> = Vec::new();
        for if_node in query::find_descendants_of_kind(*node, "if_statement") {
            if let Some(condition) = if_node.child_by_field_name("condition") {
                // Check if this is a direct NULL comparison
                if self.is_direct_null_check(&condition, source) {
                    // Only flag when the checked pointer is a function parameter.
                    // Inline null checks on locally-declared variables are acceptable
                    // practice; the "use a validation function" advice is primarily
                    // relevant when validating inputs at function boundaries.
                    let checked_var = extract_checked_var_name(&condition, source);
                    let params = self.collect_enclosing_params(&if_node, source);
                    if checked_var.as_deref().is_some_and(|v| params.contains(v)) {
                        // Suppress positive null guards where the param is only used
                        // inside the guarded block. Pattern: if (ptr != NULL) { use(ptr); }
                        // This is the prescribed fix per EXP34-C and should not be flagged.
                        let suppress = checked_var.as_ref().is_some_and(|var_name| {
                            is_positive_guard(&condition, source)
                                && !is_param_used_after_if(&if_node, var_name, source)
                        });
                        if !suppress {
                            candidates.push((if_node, condition));
                        }
                    }
                }
            }
        }

        // Require real evidence before firing: either multiple ad hoc checks
        // exist somewhere in the file (duplication), or a shared validator is
        // already defined but bypassed at these sites (inconsistency). A
        // single isolated guard in a file with no existing validator is the
        // standard, accepted idiom and must not be flagged on its own.
        if candidates.is_empty() {
            return;
        }
        if candidates.len() < 2 && !has_existing_validator {
            return;
        }

        for (_if_node, condition) in &candidates {
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                message: "Direct NULL check for pointer validation. \
                         Define and use a dedicated pointer validation function \
                         instead of ad-hoc NULL checks. This centralizes validation \
                         logic and allows platform-specific enhancements."
                    .to_string(),
                severity: self.severity(),
                line: condition.start_position().row + 1,
                column: condition.start_position().column + 1,
                file_path: String::new(),
                suggestion: Some(
                    "Create a validation function like 'int valid(void *ptr)' \
                     and use 'if (!valid(ptr))' instead of 'if (ptr == NULL)'"
                        .to_string(),
                ),
                requires_manual_review: Some(true),
            });
        }
    }

    /// Check if a condition is a direct NULL comparison (e.g., ptr == NULL, ptr != NULL, !ptr)
    fn is_direct_null_check(&self, condition: &Node, source: &str) -> bool {
        let condition_text = get_node_text(condition, source);

        // Check for explicit NULL pointer comparisons only.
        // We intentionally exclude "== 0" and "!= 0" because these are very common
        // for checking integer return values (e.g., fclose() == 0, system() != 0)
        // and generate massive false positives in non-pointer contexts.
        if condition_text.contains("== NULL") || condition_text.contains("!= NULL") {
            // Make sure it's not a function call (which would be a validation function)
            // If it contains a function call, it's likely using a validation function
            if !self.appears_to_be_validation_function_call(condition, source) {
                return true;
            }
        }

        // Check for unary not operator on a pointer
        if condition.kind() == "unary_expression" {
            if let Some(operator) = condition.child_by_field_name("operator") {
                let op_text = get_node_text(&operator, source);
                if op_text == "!" {
                    if let Some(argument) = condition.child_by_field_name("argument") {
                        // If the argument is just an identifier (not a function call), it's a direct check
                        if argument.kind() == "identifier" {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Check if the condition appears to call a validation function
    fn appears_to_be_validation_function_call(&self, condition: &Node, source: &str) -> bool {
        // Look for call_expression nodes
        self.contains_call_expression(condition, source)
    }

    fn contains_call_expression(&self, node: &Node, _source: &str) -> bool {
        query::find_first_descendant(*node, |n| n.kind() == "call_expression").is_some()
    }

    /// Check for sizeof(pointer) misuse in allocation/memory functions.
    /// Detects patterns like `malloc(sizeof(ptr))` where ptr is a pointer variable
    /// (should be `sizeof(*ptr)`) and `memset(buf, 0, sizeof(buf))` where buf is
    /// a pointer parameter.
    fn check_sizeof_pointer_misuse(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func) = call_node.child_by_field_name("function") {
                let func_name = get_node_text(&func, source);
                if matches!(
                    func_name,
                    "malloc" | "calloc" | "realloc" | "memset" | "memcpy" | "memmove"
                ) {
                    if let Some(args) = call_node.child_by_field_name("arguments") {
                        self.check_sizeof_args_in_call(
                            func_name, &args, &call_node, source, violations,
                        );
                    }
                }
            }
        }
    }

    /// Check arguments of memory functions for sizeof(pointer) misuse
    fn check_sizeof_args_in_call(
        &self,
        func_name: &str,
        args: &Node,
        call_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let mut cursor = args.walk();
        for child in args.children(&mut cursor) {
            if child.kind() == "(" || child.kind() == ")" || child.kind() == "," {
                continue;
            }
            // Check this argument and any nested sizeof within it
            self.find_sizeof_pointer_in_expr(&child, func_name, call_node, source, violations);
        }
    }

    /// Recursively look for sizeof(identifier) where identifier is a pointer
    fn find_sizeof_pointer_in_expr(
        &self,
        node: &Node,
        func_name: &str,
        call_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() == "sizeof_expression" {
            // sizeof can be `sizeof(expr)` or `sizeof expr`
            // Look for a parenthesized_expression containing a single identifier
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "parenthesized_expression" {
                        // Get inner: sizeof(X) — check if X is an identifier
                        if let Some(inner) = child.child(1) {
                            if inner.kind() == "identifier" {
                                let var_name = get_node_text(&inner, source);
                                if self.is_pointer_variable(&inner, var_name, source) {
                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        message: format!(
                                            "sizeof({}) returns the size of a pointer ({}), not the pointed-to data. \
                                             Use sizeof(*{}) or sizeof(type) in {}() call.",
                                            var_name,
                                            if cfg!(target_pointer_width = "64") { "8 bytes" } else { "4 bytes" },
                                            var_name,
                                            func_name,
                                        ),
                                        severity: Severity::Medium,
                                        line: node.start_position().row + 1,
                                        column: node.start_position().column + 1,
                                        file_path: String::new(),
                                        suggestion: Some(format!(
                                            "Replace sizeof({}) with sizeof(*{}) to get the size of the pointed-to type",
                                            var_name, var_name,
                                        )),
                                        requires_manual_review: Some(false),
                                    });
                                }
                            }
                        }
                    }
                }
            }
            return; // Don't recurse into sizeof
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.find_sizeof_pointer_in_expr(&child, func_name, call_node, source, violations);
            }
        }
    }

    /// Check if a variable is declared as a pointer type by walking up to the
    /// enclosing function and scanning declarations and parameters.
    fn is_pointer_variable(&self, node: &Node, var_name: &str, source: &str) -> bool {
        // Walk up to enclosing function
        let mut current = node.parent();
        while let Some(p) = current {
            if p.kind() == "function_definition" {
                // Check parameters
                if self.is_pointer_param(&p, var_name, source) {
                    return true;
                }
                // Check local declarations in function body
                if let Some(body) = p.child_by_field_name("body") {
                    if self.is_pointer_local_var(&body, var_name, source) {
                        return true;
                    }
                }
                return false;
            }
            current = p.parent();
        }
        false
    }

    /// Check if var_name is declared as a pointer parameter
    fn is_pointer_param(&self, func_node: &Node, var_name: &str, source: &str) -> bool {
        let params = self.extract_pointer_param_names(func_node, source);
        params.contains(var_name)
    }

    /// Check if var_name is a local pointer variable
    fn is_pointer_local_var(&self, body: &Node, var_name: &str, source: &str) -> bool {
        let mut cursor = body.walk();
        for child in body.children(&mut cursor) {
            if child.kind() == "declaration" {
                // Check if the declaration has a pointer declarator for this var
                let mut decl_cursor = child.walk();
                for decl_child in child.children(&mut decl_cursor) {
                    if decl_child.kind() == "init_declarator" {
                        if let Some(declarator) = decl_child.child_by_field_name("declarator") {
                            if declarator.kind() == "pointer_declarator" {
                                if let Some(id) = find_identifier_in_node(&declarator, source) {
                                    if id == var_name {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }
}

/// Extract the variable name being null-checked from a condition node.
/// Handles: `ptr == NULL`, `NULL == ptr`, `ptr != NULL`, `NULL != ptr`, `!ptr`
fn extract_checked_var_name(condition: &Node, source: &str) -> Option<String> {
    // Binary expression: ptr == NULL or ptr != NULL (or reversed)
    if condition.kind() == "binary_expression" {
        let left = condition.child_by_field_name("left")?;
        let right = condition.child_by_field_name("right")?;
        let left_text = get_node_text(&left, source);
        let right_text = get_node_text(&right, source);
        if right_text == "NULL" && left.kind() == "identifier" {
            return Some(left_text.to_string());
        }
        if left_text == "NULL" && right.kind() == "identifier" {
            return Some(right_text.to_string());
        }
        return None;
    }

    // Parenthesized expression: (ptr == NULL)
    if condition.kind() == "parenthesized_expression" {
        if let Some(inner) = condition.child(1) {
            return extract_checked_var_name(&inner, source);
        }
    }

    // Unary not: !ptr
    if condition.kind() == "unary_expression" {
        if let Some(op) = condition.child_by_field_name("operator") {
            if get_node_text(&op, source) == "!" {
                if let Some(arg) = condition.child_by_field_name("argument") {
                    if arg.kind() == "identifier" {
                        return Some(get_node_text(&arg, source).to_string());
                    }
                }
            }
        }
    }

    None
}

/// Recursively find the first identifier inside a declarator node.
fn find_identifier_in_node(node: &Node, source: &str) -> Option<String> {
    if node.kind() == "identifier" {
        return Some(get_node_text(node, source).to_string());
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if let Some(id) = find_identifier_in_node(&child, source) {
                return Some(id);
            }
        }
    }
    None
}

/// Returns true if the condition is a positive null guard — i.e. the if-block
/// is entered only when the pointer is non-NULL.
/// Matches: `ptr != NULL`, `NULL != ptr`, bare `ptr` truthiness.
/// Does NOT match: `ptr == NULL`, `!ptr` (those are negative/early-return guards).
fn is_positive_guard(condition: &Node, source: &str) -> bool {
    let text = get_node_text(condition, source);

    // != NULL patterns
    if text.contains("!= NULL") || text.contains("!=NULL") {
        return true;
    }
    if text.contains("NULL !=") || text.contains("NULL!=") {
        return true;
    }

    // Bare truthiness: condition is just the identifier (possibly parenthesized)
    // e.g. if (ptr) or if (ptr && ...)
    if condition.kind() == "identifier" {
        return true;
    }
    if condition.kind() == "parenthesized_expression" {
        if let Some(inner) = condition.child(1) {
            if inner.kind() == "identifier" {
                return true;
            }
        }
    }

    false
}

/// Check if `var_name` is used in any sibling statement after the given if_statement node.
fn is_param_used_after_if(if_node: &Node, var_name: &str, source: &str) -> bool {
    let parent = match if_node.parent() {
        Some(p) => p,
        None => return false,
    };

    let mut found_if = false;
    for i in 0..parent.child_count() {
        if let Some(sibling) = parent.child(i) {
            if sibling.id() == if_node.id() {
                found_if = true;
                continue;
            }
            if found_if && contains_identifier(&sibling, var_name, source) {
                return true;
            }
        }
    }

    false
}

/// Check whether the file already defines a dedicated pointer-validation
/// function — i.e. a function whose entire body is a single `return`
/// statement comparing its argument against NULL (or negating it), matching
/// the "compliant" shape from CERT's own example:
/// `int valid(void *ptr) { return ptr != NULL; }`.
/// If such a function exists, any ad hoc NULL check elsewhere in the file is
/// a real inconsistency (a shared validator was available but not used),
/// which is stronger evidence than a lone guard on its own.
fn file_defines_validator_function(root: &Node, source: &str) -> bool {
    for func in query::find_descendants_of_kind(*root, "function_definition") {
        let Some(body) = func.child_by_field_name("body") else {
            continue;
        };
        if body.kind() != "compound_statement" {
            continue;
        }
        // Collect the non-brace statements in the body.
        let mut cursor = body.walk();
        let statements: Vec<Node> = body
            .children(&mut cursor)
            .filter(|c| c.kind() != "{" && c.kind() != "}")
            .collect();
        if statements.len() != 1 {
            continue;
        }
        let stmt = statements[0];
        if stmt.kind() != "return_statement" {
            continue;
        }
        // The return value should itself be a NULL comparison or negation,
        // i.e. the function's only job is validity checking.
        if let Some(value) = stmt.child(1) {
            if value.kind() == "binary_expression" {
                let text = get_node_text(&value, source);
                if text.contains("NULL") {
                    return true;
                }
            } else if value.kind() == "unary_expression" {
                if let Some(op) = value.child_by_field_name("operator") {
                    if get_node_text(&op, source) == "!" {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Check if a node contains an identifier matching `name`.
fn contains_identifier(node: &Node, name: &str, source: &str) -> bool {
    query::find_first_descendant(*node, |n| {
        n.kind() == "identifier" && get_node_text(&n, source) == name
    })
    .is_some()
}
