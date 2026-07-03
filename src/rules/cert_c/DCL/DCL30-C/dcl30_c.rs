//! DCL30-C: Declare objects with appropriate storage durations
//!
//! This rule detects when pointers to automatic storage (local variables) are
//! returned or assigned to longer-lived storage, causing dangling pointer issues.
//!
//! VIOLATIONS:
//! - return local_array;              // Returning pointer to local
//! - *ptr_param = local;              // Assigning local to output parameter
//! - global_ptr = local_array;        // Assigning local to global
//!
//! COMPLIANT:
//! - void init_array(char *array)    // Pass array as parameter instead
//! - return malloc(...);              // Return allocated memory
//! - static char array[10];           // Use static storage for long-lived data

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Dcl30C;

impl CertRule for Dcl30C {
    fn rule_id(&self) -> &'static str {
        "DCL30-C"
    }

    fn description(&self) -> &'static str {
        "Declare objects with appropriate storage durations"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "DCL30-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        for found in
            query::find_descendants_of_kinds(*node, &["return_statement", "assignment_expression"])
        {
            match found.kind() {
                // Check return statements for local variable pointers
                "return_statement" => {
                    if let Some(violation) = self.check_return_local(&found, source) {
                        violations.push(violation);
                    }
                }
                // Check assignments for local variables assigned to globals or output params
                "assignment_expression" => {
                    if let Some(violation) = self.check_assignment_storage_duration(&found, source)
                    {
                        violations.push(violation);
                    }
                }
                _ => {}
            }
        }

        violations
    }
}

impl Dcl30C {
    /// Recursively collect file-scope declarations, including inside preprocessor blocks.
    fn collect_file_scope_declarations<'a>(node: &Node<'a>, decls: &mut Vec<Node<'a>>) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "declaration" {
                    decls.push(child);
                } else if child.kind().starts_with("preproc_") {
                    Self::collect_file_scope_declarations(&child, decls);
                }
            }
        }
    }

    /// Check if a return statement returns a pointer to a local variable
    fn check_return_local(&self, return_node: &Node, source: &str) -> Option<RuleViolation> {
        // Get the returned expression
        for i in 0..return_node.child_count() {
            if let Some(child) = return_node.child(i) {
                if child.kind() == "identifier" {
                    let var_name = ast_utils::get_node_text(&child, source).to_string();

                    // Only flag if the local is a pointer or array type.
                    // Returning a scalar by value copies the value — it is safe and
                    // is NOT what DCL30-C is about.
                    if self.is_local_variable(&child, source)
                        && self.local_var_is_pointer_or_array(&child, &var_name, source)
                    {
                        // Don't flag if the pointer was assigned from heap allocation
                        // (malloc, calloc, realloc, or wrapper functions). Returning
                        // a heap pointer via a local variable is safe — the allocated
                        // memory outlives the function scope. This is the standard
                        // factory/constructor pattern in C.
                        if self.local_var_is_heap_allocated(&child, &var_name, source) {
                            return None;
                        }

                        // Don't flag if the pointer was assigned from a static
                        // variable's address (e.g., ptrCharString = &staticArray[1]).
                        // Static storage outlives the function scope.
                        if self.local_ptr_points_to_static(&child, &var_name, source) {
                            return None;
                        }

                        let start_point = return_node.start_position();

                        return Some(RuleViolation {
                            rule_id: "DCL30-C".to_string(),
                            severity: Severity::High,
                            message: format!(
                                "Function returns pointer to local variable '{}' with automatic storage duration",
                                var_name
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Use static storage, allocated memory, or pass output buffer as parameter".to_string()
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
        None
    }

    /// Returns true if the local variable named `var_name` is declared as a pointer
    /// or array type in the enclosing function body.
    fn local_var_is_pointer_or_array(&self, var_node: &Node, var_name: &str, source: &str) -> bool {
        // Walk up to the function body
        let mut current = var_node.parent();
        let mut function_body: Option<Node> = None;
        while let Some(node) = current {
            if node.kind() == "compound_statement" {
                if let Some(parent) = node.parent() {
                    if parent.kind() == "function_definition" {
                        function_body = Some(node);
                        break;
                    }
                }
            }
            current = node.parent();
        }
        let body = match function_body {
            Some(b) => b,
            None => return false,
        };
        self.find_pointer_or_array_declaration(&body, var_name, source)
    }

    /// Check if a local pointer variable was initialized from a heap allocation
    /// (malloc, calloc, realloc, or wrapper functions). Returning such a pointer
    /// is safe because the heap memory outlives the function scope.
    fn local_var_is_heap_allocated(&self, var_node: &Node, var_name: &str, source: &str) -> bool {
        // Walk up to the function body
        let mut current = var_node.parent();
        let mut function_body: Option<Node> = None;
        while let Some(node) = current {
            if node.kind() == "compound_statement" {
                if let Some(parent) = node.parent() {
                    if parent.kind() == "function_definition" {
                        function_body = Some(node);
                        break;
                    }
                }
            }
            current = node.parent();
        }
        let body = match function_body {
            Some(b) => b,
            None => return false,
        };
        self.find_heap_allocation_for_var(&body, var_name, source)
    }

    /// Check if a local pointer variable was assigned from the address of a
    /// `static` local variable (e.g., `ptr = &static_array[i]`). Returning
    /// such a pointer is safe because static storage outlives the function.
    fn local_ptr_points_to_static(&self, var_node: &Node, var_name: &str, source: &str) -> bool {
        let mut current = var_node.parent();
        let mut function_body: Option<Node> = None;
        while let Some(node) = current {
            if node.kind() == "compound_statement" {
                if let Some(parent) = node.parent() {
                    if parent.kind() == "function_definition" {
                        function_body = Some(node);
                        break;
                    }
                }
            }
            current = node.parent();
        }
        let body = match function_body {
            Some(b) => b,
            None => return false,
        };
        self.find_static_address_assignment(&body, var_name, source)
    }

    /// Scan function body for assignments like `var = &something` or
    /// `var = &something[i]` where `something` is declared `static`.
    fn find_static_address_assignment(&self, body: &Node, var_name: &str, source: &str) -> bool {
        for i in 0..body.child_count() {
            if let Some(child) = body.child(i) {
                if child.kind() == "expression_statement" {
                    if let Some(expr) = child.child(0) {
                        if expr.kind() == "assignment_expression" {
                            if let (Some(left), Some(right)) = (
                                expr.child_by_field_name("left"),
                                expr.child_by_field_name("right"),
                            ) {
                                let left_text = ast_utils::get_node_text(&left, source);
                                if left_text == var_name {
                                    if let Some(src_var) =
                                        self.extract_address_of_target(&right, source)
                                    {
                                        if self.is_static_local(body, &src_var, source) {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if child.kind() == "compound_statement" || child.kind() == "if_statement" {
                    if self.find_static_address_assignment(&child, var_name, source) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Extract the base variable name from an address-of expression.
    /// `&charString` → Some("charString"), `&charString[1]` → Some("charString")
    fn extract_address_of_target(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "pointer_expression" {
            // &expr — get the operand
            let text = ast_utils::get_node_text(node, source);
            if text.starts_with('&') {
                if let Some(operand) = node.child(1) {
                    return self.extract_base_identifier(&operand, source);
                }
            }
        }
        None
    }

    /// Extract the base identifier from an expression.
    /// `charString` → Some("charString"), `charString[1]` → Some("charString")
    fn extract_base_identifier(&self, node: &Node, source: &str) -> Option<String> {
        match node.kind() {
            "identifier" => Some(ast_utils::get_node_text(node, source).to_string()),
            "subscript_expression" => {
                // array[index] — get the array part
                if let Some(arr) = node.child(0) {
                    self.extract_base_identifier(&arr, source)
                } else {
                    None
                }
            }
            "field_expression" => {
                // struct.field — get the struct part
                if let Some(obj) = node.child(0) {
                    self.extract_base_identifier(&obj, source)
                } else {
                    None
                }
            }
            "parenthesized_expression" => {
                if let Some(inner) = node.child(1) {
                    self.extract_base_identifier(&inner, source)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Check if `var_name` is declared with `static` storage in the function body.
    fn is_static_local(&self, body: &Node, var_name: &str, source: &str) -> bool {
        for i in 0..body.child_count() {
            if let Some(child) = body.child(i) {
                if child.kind() == "declaration" {
                    if self.declaration_contains_var_by_name(&child, var_name, source) {
                        let decl_text = ast_utils::get_node_text(&child, source);
                        return decl_text.contains("static");
                    }
                }
                if child.kind() == "compound_statement" {
                    if self.is_static_local(&child, var_name, source) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Search a function body for evidence that `var_name` holds a heap pointer
    /// or a pointer copied from another (non-local-address) source.
    fn find_heap_allocation_for_var(&self, body: &Node, var_name: &str, source: &str) -> bool {
        for i in 0..body.child_count() {
            if let Some(child) = body.child(i) {
                if child.kind() == "declaration" {
                    if self.declaration_contains_var_by_name(&child, var_name, source) {
                        // Check initializer for alloc
                        if self.declaration_has_alloc_initializer(&child, source) {
                            return true;
                        }
                        // If initialized to NULL, check for later alloc assignment
                        if self.declaration_has_null_initializer(&child, source) {
                            if self.has_alloc_assignment_in_body(body, var_name, source) {
                                return true;
                            }
                            // Also safe: pointer assigned from struct member access or function call
                            // (not address-of local). If only assigned from field_expression or
                            // call_expression, it holds a non-local pointer.
                            if self.only_assigned_safe_sources(body, var_name, source) {
                                return true;
                            }
                        }
                    }
                }
                if child.kind() == "compound_statement" {
                    if self.find_heap_allocation_for_var(&child, var_name, source) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if a declaration initializes the variable to NULL.
    fn declaration_has_null_initializer(&self, decl: &Node, source: &str) -> bool {
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        let text = ast_utils::get_node_text(&value, source);
                        return text == "NULL" || text == "0" || text == "nullptr";
                    }
                }
            }
        }
        false
    }

    /// Scan function body for `var_name = alloc(...)` assignments.
    fn has_alloc_assignment_in_body(&self, body: &Node, var_name: &str, source: &str) -> bool {
        for i in 0..body.child_count() {
            if let Some(child) = body.child(i) {
                if child.kind() == "expression_statement" {
                    if let Some(expr) = child.child(0) {
                        if expr.kind() == "assignment_expression" {
                            if let (Some(left), Some(right)) = (
                                expr.child_by_field_name("left"),
                                expr.child_by_field_name("right"),
                            ) {
                                let left_text = ast_utils::get_node_text(&left, source);
                                if left_text == var_name && self.is_alloc_expression(&right, source)
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
                // Recurse into if-blocks, etc.
                if child.kind() == "if_statement" || child.kind() == "compound_statement" {
                    if self.has_alloc_assignment_in_body(&child, var_name, source) {
                        return true;
                    }
                }
                if let Some(consequence) = child.child_by_field_name("consequence") {
                    if self.has_alloc_assignment_in_body(&consequence, var_name, source) {
                        return true;
                    }
                }
                if let Some(alternative) = child.child_by_field_name("alternative") {
                    if self.has_alloc_assignment_in_body(&alternative, var_name, source) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if all assignments to `var_name` in the body are from safe sources
    /// (struct member access, function call, NULL) — not from address-of-local.
    fn only_assigned_safe_sources(&self, body: &Node, var_name: &str, source: &str) -> bool {
        let mut found_any_assignment = false;
        for stmt in query::find_descendants_of_kind(*body, "expression_statement") {
            if let Some(expr) = stmt.child(0) {
                if expr.kind() == "assignment_expression" {
                    if let (Some(left), Some(right)) = (
                        expr.child_by_field_name("left"),
                        expr.child_by_field_name("right"),
                    ) {
                        let left_text = ast_utils::get_node_text(&left, source);
                        if left_text == var_name {
                            found_any_assignment = true;
                            // Unsafe: address-of expression
                            if right.kind() == "pointer_expression" {
                                return false;
                            }
                            let rt = ast_utils::get_node_text(&right, source);
                            if rt.starts_with('&') {
                                return false;
                            }
                            // Safe sources: field_expression, call_expression,
                            // subscript_expression, identifier, NULL
                        }
                    }
                }
            }
        }
        found_any_assignment
    }

    /// Check if a declaration has an initializer that is a heap allocation call.
    fn declaration_has_alloc_initializer(&self, decl: &Node, source: &str) -> bool {
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        return self.is_alloc_expression(&value, source);
                    }
                }
            }
        }
        false
    }

    /// Check if an expression is a heap allocation (malloc, calloc, realloc, or
    /// wrapper). Handles cast expressions like `(Type *)malloc(...)`.
    fn is_alloc_expression(&self, node: &Node, source: &str) -> bool {
        match node.kind() {
            "call_expression" => {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_name = ast_utils::get_node_text(&func, source);
                    let upper = func_name.to_uppercase();
                    return func_name == "malloc"
                        || func_name == "calloc"
                        || func_name == "realloc"
                        || func_name == "strdup"
                        || func_name == "strndup"
                        || upper.contains("MALLOC")
                        || upper.contains("CALLOC")
                        || upper.contains("REALLOC")
                        || upper.contains("ALLOC")
                        || upper.contains("STRDUP");
                }
                false
            }
            "cast_expression" => {
                // (Type *)malloc(...) — unwrap the cast
                if let Some(value) = node.child_by_field_name("value") {
                    self.is_alloc_expression(&value, source)
                } else {
                    false
                }
            }
            "parenthesized_expression" => {
                if let Some(inner) = node.child(1) {
                    self.is_alloc_expression(&inner, source)
                } else {
                    false
                }
            }
            "conditional_expression" => {
                // (cond) ? alloc_expr : NULL — check both branches
                if let Some(consequence) = node.child_by_field_name("consequence") {
                    if self.is_alloc_expression(&consequence, source) {
                        return true;
                    }
                }
                if let Some(alternative) = node.child_by_field_name("alternative") {
                    if self.is_alloc_expression(&alternative, source) {
                        return true;
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Search a compound statement for a declaration of `var_name` that is a
    /// pointer (`*`) or array (`[`) declarator.
    fn find_pointer_or_array_declaration(&self, body: &Node, var_name: &str, source: &str) -> bool {
        for i in 0..body.child_count() {
            if let Some(child) = body.child(i) {
                if child.kind() == "declaration" {
                    if self.declaration_contains_var_by_name(&child, var_name, source) {
                        // Check the declarator kind: pointer_declarator or array_declarator
                        // means it is a pointer/array type.
                        return self.declaration_has_pointer_or_array_declarator(&child);
                    }
                }
                if child.kind() == "compound_statement" {
                    if self.find_pointer_or_array_declaration(&child, var_name, source) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if a declaration declares `var_name` by comparing actual identifier text.
    fn declaration_contains_var_by_name(
        &self,
        decl_node: &Node,
        var_name: &str,
        source: &str,
    ) -> bool {
        for i in 0..decl_node.child_count() {
            if let Some(child) = decl_node.child(i) {
                if matches!(
                    child.kind(),
                    "init_declarator" | "array_declarator" | "pointer_declarator" | "identifier"
                ) {
                    if self.contains_identifier_by_name(&child, var_name, source) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// True if the declaration node contains a pointer_declarator or array_declarator,
    /// indicating the declared variable is a pointer or array.
    fn declaration_has_pointer_or_array_declarator(&self, decl_node: &Node) -> bool {
        for i in 0..decl_node.child_count() {
            if let Some(child) = decl_node.child(i) {
                match child.kind() {
                    "pointer_declarator" | "array_declarator" => return true,
                    "init_declarator" => {
                        // init_declarator wraps the actual declarator
                        for j in 0..child.child_count() {
                            if let Some(inner) = child.child(j) {
                                if matches!(inner.kind(), "pointer_declarator" | "array_declarator")
                                {
                                    return true;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        false
    }

    /// Check if an assignment assigns a local variable to global or output parameter
    fn check_assignment_storage_duration(
        &self,
        assignment_node: &Node,
        source: &str,
    ) -> Option<RuleViolation> {
        // Get left and right sides of assignment
        let left = assignment_node.child_by_field_name("left")?;
        let right = assignment_node.child_by_field_name("right")?;

        // Check if right side is a local variable
        if right.kind() == "identifier" {
            let right_var = ast_utils::get_node_text(&right, source).to_string();

            if !self.is_local_variable(&right, source) {
                return None;
            }

            // Check if left side is a pointer dereference or global
            match left.kind() {
                "pointer_expression" => {
                    // *ptr_param = local; pattern — only flag if local is a pointer/array
                    // Assigning a scalar value (e.g., *sock = sockfd where sockfd is int)
                    // just copies the value, not the address. Only pointer assignments escape.
                    if !self.local_var_is_pointer_or_array(&right, &right_var, source) {
                        return None;
                    }
                    let start_point = assignment_node.start_position();
                    return Some(RuleViolation {
                        rule_id: "DCL30-C".to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Local variable '{}' assigned through pointer parameter - address will be invalid when function returns",
                            right_var
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Copy data instead of assigning pointer, or use static/allocated storage".to_string()
                        ),
                        ..Default::default()
                    });
                }
                "identifier"
                    // Check if left is a global variable (declared outside function)
                    if self.is_global_or_static(&left, source) => {
                        // Only flag when the local is a pointer or array type.
                        // Assigning a scalar value (e.g., global_int = local_int)
                        // just copies the value — no dangling reference is created.
                        if !self.local_var_is_pointer_or_array(&right, &right_var, source) {
                            return None;
                        }

                        let left_var = ast_utils::get_node_text(&left, source).to_string();

                        // Check if global is reassigned later in the same function (like p = NULL)
                        if self.is_global_reassigned_later(assignment_node, &left_var, source) {
                            // Safe pattern: global is reset before function returns
                            return None;
                        }

                        let start_point = assignment_node.start_position();

                        return Some(RuleViolation {
                            rule_id: "DCL30-C".to_string(),
                            severity: Severity::High,
                            message: format!(
                                "Local variable '{}' assigned to global/static variable '{}' - creates dangling pointer",
                                right_var, left_var
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Use static storage for local variable or copy data instead of assigning pointer".to_string()
                            ),
                            ..Default::default()
                        });
                    }
                _ => {}
            }
        }

        None
    }

    /// Check if a variable is declared locally in a function (automatic storage)
    fn is_local_variable(&self, var_node: &Node, source: &str) -> bool {
        let var_name = ast_utils::get_node_text(var_node, source);

        // Find the containing function
        let mut current = var_node.parent();
        let mut function_body: Option<Node> = None;

        while let Some(node) = current {
            if node.kind() == "compound_statement" {
                if let Some(parent) = node.parent() {
                    if parent.kind() == "function_definition" {
                        function_body = Some(node);
                        break;
                    }
                }
            }
            current = node.parent();
        }

        let body = match function_body {
            Some(b) => b,
            None => return false,
        };

        // Search for declaration of this variable in function body
        self.find_local_declaration(&body, &var_name, source)
    }

    /// Find if a variable is declared locally (not static)
    fn find_local_declaration(&self, body: &Node, var_name: &str, source: &str) -> bool {
        for i in 0..body.child_count() {
            if let Some(child) = body.child(i) {
                if child.kind() == "declaration" {
                    // Check if this declaration declares our variable
                    if self.declaration_contains_var(&child, var_name, source) {
                        // Check if it's NOT static
                        let decl_text = ast_utils::get_node_text(&child, source);
                        return !decl_text.contains("static");
                    }
                }
                // Recursively search compound statements
                if child.kind() == "compound_statement" {
                    if self.find_local_declaration(&child, var_name, source) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if a declaration contains a specific variable name
    fn declaration_contains_var(&self, decl_node: &Node, var_name: &str, source: &str) -> bool {
        for i in 0..decl_node.child_count() {
            if let Some(child) = decl_node.child(i) {
                // Look for init_declarator or direct declarators
                if matches!(
                    child.kind(),
                    "init_declarator" | "array_declarator" | "pointer_declarator" | "identifier"
                ) {
                    // Search recursively for identifier nodes using text comparison
                    if self.contains_identifier_by_name(&child, var_name, source) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if a node tree contains an identifier with given name.
    fn contains_identifier_by_name(&self, node: &Node, var_name: &str, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            n.kind() == "identifier" && ast_utils::get_node_text(&n, source) == var_name
        })
        .is_some()
    }

    /// Check if a global variable is reassigned later in the same function
    /// (e.g., p = NULL after p = local_var makes it safe)
    fn is_global_reassigned_later(
        &self,
        assignment_node: &Node,
        var_name: &str,
        source: &str,
    ) -> bool {
        // Find the containing function body
        let mut current = assignment_node.parent();
        let mut function_body: Option<Node> = None;

        while let Some(node) = current {
            if node.kind() == "compound_statement" {
                if let Some(parent) = node.parent() {
                    if parent.kind() == "function_definition" {
                        function_body = Some(node);
                        break;
                    }
                }
            }
            current = node.parent();
        }

        let body = match function_body {
            Some(b) => b,
            None => return false,
        };

        // Find the expression_statement containing the current assignment
        let mut current_stmt: Option<Node> = None;
        let mut node = Some(*assignment_node);
        while let Some(n) = node {
            if n.kind() == "expression_statement" {
                current_stmt = Some(n);
                break;
            }
            node = n.parent();
        }

        let current_expr_stmt = match current_stmt {
            Some(s) => s,
            None => return false,
        };

        // Find all statements after this assignment
        let statements = self.get_statements_in_body(&body);
        let mut found_current = false;

        for stmt in statements {
            // Skip until we find the current statement
            if stmt.id() == current_expr_stmt.id() {
                found_current = true;
                continue; // Skip the current statement itself
            }

            if found_current {
                // Check if this statement assigns to the same variable
                if self.assigns_to_variable(&stmt, var_name, source) {
                    return true;
                }
            }
        }

        false
    }

    /// Get all statements within a compound statement (flattened)
    fn get_statements_in_body<'a>(&self, body: &Node<'a>) -> Vec<Node<'a>> {
        let mut statements = Vec::new();
        for i in 0..body.child_count() {
            if let Some(child) = body.child(i) {
                if child.kind() == "expression_statement" {
                    statements.push(child);
                }
            }
        }
        statements
    }

    /// Check if a statement assigns to a specific variable
    fn assigns_to_variable(&self, stmt: &Node, var_name: &str, source: &str) -> bool {
        if stmt.kind() == "expression_statement" {
            for i in 0..stmt.child_count() {
                if let Some(child) = stmt.child(i) {
                    if child.kind() == "assignment_expression" {
                        if let Some(left) = child.child_by_field_name("left") {
                            let left_text = ast_utils::get_node_text(&left, source);
                            if left_text == var_name {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if a variable is declared at global scope or with static storage
    fn is_global_or_static(&self, var_node: &Node, source: &str) -> bool {
        // Get variable name
        let var_name = ast_utils::get_node_text(var_node, source);

        // Find the translation unit (root)
        let mut current = Some(*var_node);
        let mut root: Option<Node> = None;

        while let Some(node) = current {
            if node.kind() == "translation_unit" {
                root = Some(node);
                break;
            }
            current = node.parent();
        }

        let translation_unit = match root {
            Some(r) => r,
            None => return false,
        };

        // Search for global declaration of this variable, including inside preprocessor blocks
        let mut decls = Vec::new();
        Self::collect_file_scope_declarations(&translation_unit, &mut decls);
        for child in &decls {
            if self.contains_identifier_by_name(child, &var_name, source) {
                return true;
            }
        }

        false
    }
}
