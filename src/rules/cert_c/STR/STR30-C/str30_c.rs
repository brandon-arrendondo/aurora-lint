use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Str30C;

impl CertRule for Str30C {
    fn rule_id(&self) -> &'static str {
        "STR30-C"
    }

    fn description(&self) -> &'static str {
        "Do not attempt to modify string literals"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "STR30-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let mut analyzer = StringLiteralAnalyzer::new();

        // Analyze the current node and its subtree
        analyzer.analyze_node(node, source, &mut violations);

        violations
    }
}

struct StringLiteralAnalyzer {
    // Track variables that point to string literals
    string_literal_vars: HashSet<String>,
    // Track double pointers to string literals (char **ptr = &str)
    double_pointer_vars: HashSet<String>,
    // Track function parameters that might point to string literals (const char*)
    const_char_params: HashSet<String>,
    // Track results of strrchr/strchr on parameters
    search_result_vars: HashSet<String>,
}

impl StringLiteralAnalyzer {
    fn new() -> Self {
        Self {
            string_literal_vars: HashSet::new(),
            double_pointer_vars: HashSet::new(),
            const_char_params: HashSet::new(),
            search_result_vars: HashSet::new(),
        }
    }

    fn analyze_node(&mut self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for node in query::find_descendants(*node, |_| true) {
            let node = &node;
            match node.kind() {
                "function_definition" => {
                    // Extract const char* parameters from function signature
                    self.extract_const_params(node, source);
                }
                "declaration" => {
                    self.process_declaration(node, source, violations);
                }
                "assignment_expression" => {
                    self.process_assignment(node, source, violations);
                }
                "call_expression" => {
                    self.check_function_call(node, source, violations);
                }
                "subscript_expression" => {
                    self.check_array_modification(node, source, violations);
                }
                "pointer_expression" => {
                    self.check_pointer_modification(node, source, violations);
                }
                _ => {}
            }
        }
    }

    /// Extract const char* parameters from function definition
    fn extract_const_params(&mut self, node: &Node, source: &str) {
        // Look for the declarator which contains the parameter_list
        if let Some(declarator) = node.child_by_field_name("declarator") {
            self.find_const_params_in_declarator(&declarator, source);
        }
    }

    fn find_const_params_in_declarator(&mut self, node: &Node, source: &str) {
        if node.kind() == "parameter_list" {
            for i in 0..node.child_count() {
                if let Some(param) = node.child(i) {
                    if param.kind() == "parameter_declaration" {
                        let param_text = ast_utils::get_node_text_owned(&param, source);
                        // Check for const char* pattern
                        if param_text.contains("const") && param_text.contains("char") {
                            // Extract parameter name
                            if let Some(decl) = param.child_by_field_name("declarator") {
                                let param_name = self.get_variable_name(&decl, source);
                                if param_name != "unknown" {
                                    self.const_char_params.insert(param_name);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Recurse into children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.find_const_params_in_declarator(&child, source);
            }
        }
    }

    fn process_declaration(
        &mut self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for i in 0..node.child_count() {
            let Some(child) = node.child(i) else { continue };
            if child.kind() != "init_declarator" {
                continue;
            }
            let Some(declarator) = child.child_by_field_name("declarator") else {
                continue;
            };
            // Check if this is an array declaration vs a pointer
            let is_array = self.is_array_declarator(&declarator);
            let var_name = self.get_variable_name(&declarator, source);

            if let Some(value) = child.child_by_field_name("value") {
                self.classify_init_declarator_value(
                    &declarator,
                    &value,
                    &var_name,
                    is_array,
                    source,
                );
            }
        }

        // Also check for uninitialized declarations that might be assigned later
        // For tracking purposes in assignment expressions
        let _ = violations; // silence unused warning
    }

    /// Classify an `init_declarator`'s initializer value against the various
    /// string-literal/search-result/double-pointer tracking heuristics, and
    /// record `var_name` into the matching tracked-variable set(s). Only
    /// pointer variables are tracked — arrays initialized with string
    /// literals are modifiable copies.
    fn classify_init_declarator_value(
        &mut self,
        declarator: &Node,
        value: &Node,
        var_name: &str,
        is_array: bool,
        source: &str,
    ) {
        // This is a pointer to a string literal
        if self.is_string_literal(value, source) && !is_array {
            self.string_literal_vars.insert(var_name.to_string());
        }

        // Track results of string search functions on literals
        // e.g., char *ptr = strchr("Hello", 'W');
        if self.is_search_result_of_literal(value, source) && !is_array {
            self.string_literal_vars.insert(var_name.to_string());
        }

        // Track results of string search functions on const char* params
        // e.g., char *ptr = strrchr(pathname, '/');
        if self.is_search_result_of_const_param(value, source) && !is_array {
            self.search_result_vars.insert(var_name.to_string());
        }

        // Track casting away const from string literal
        // e.g., char *str = (char *)cstr; where cstr points to literal
        if self.is_cast_from_literal_var(value, source) && !is_array {
            self.string_literal_vars.insert(var_name.to_string());
        }

        // Track arrays of pointers initialized with string literals
        // e.g., char *strings[] = { "first", "second" };
        if self.is_array_of_literal_pointers(declarator, value, source) {
            self.string_literal_vars.insert(var_name.to_string());
        }

        // Track double pointers to string literal vars
        // e.g., char **ptr = &str;
        if self.is_double_pointer_to_literal(value, source) {
            self.double_pointer_vars.insert(var_name.to_string());
        }

        // Track structs initialized with string literals
        // e.g., struct data d = { "literal" };
        // Check if not a char array (which is a modifiable copy)
        if value.kind() == "initializer_list"
            && self.initializer_contains_string_literal(value, source)
            && !is_array
        {
            self.string_literal_vars.insert(var_name.to_string());
        }

        // Track function call results that might return string literals
        if self.is_function_returning_literal(value, source) && !is_array {
            self.string_literal_vars.insert(var_name.to_string());
        }
    }

    /// Check if declaration is an array of pointers initialized with string literals
    fn is_array_of_literal_pointers(&self, declarator: &Node, value: &Node, source: &str) -> bool {
        // Check if value is an initializer_list with string literals
        if value.kind() != "initializer_list" {
            return false;
        }

        if !self.initializer_contains_string_literal(value, source) {
            return false;
        }

        // Pattern 1: array_declarator with pointer_declarator inside
        // e.g., char *strings[] = {"a", "b"}
        if declarator.kind() == "array_declarator" {
            // Check via field name
            if let Some(inner_declarator) = declarator.child_by_field_name("declarator") {
                if inner_declarator.kind() == "pointer_declarator" {
                    return true;
                }
            }
            // Also check by iterating children
            for i in 0..declarator.child_count() {
                if let Some(child) = declarator.child(i) {
                    if child.kind() == "pointer_declarator" {
                        return true;
                    }
                }
            }
        }

        // Pattern 2: pointer_declarator with array_declarator inside
        // (alternative tree structure depending on parsing)
        if declarator.kind() == "pointer_declarator" {
            if let Some(inner_declarator) = declarator.child_by_field_name("declarator") {
                if inner_declarator.kind() == "array_declarator" {
                    return true;
                }
            }
            // Also check by iterating children
            for i in 0..declarator.child_count() {
                if let Some(child) = declarator.child(i) {
                    if child.kind() == "array_declarator" {
                        return true;
                    }
                }
            }
        }

        // Pattern 3: Check declarator text for pointer-array pattern
        // This handles edge cases where the tree structure varies
        let decl_text = ast_utils::get_node_text_owned(declarator, source);
        if decl_text.contains('*') && decl_text.contains('[') && decl_text.contains(']') {
            return true;
        }

        false
    }

    /// Check if value is a double pointer to a tracked string literal var
    /// e.g., char **ptr = &str; where str is in string_literal_vars
    fn is_double_pointer_to_literal(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "pointer_expression" {
            // Check for & operator (address-of)
            let node_text = ast_utils::get_node_text_owned(node, source);
            if node_text.starts_with('&') {
                // Get the operand
                if let Some(argument) = node.child_by_field_name("argument") {
                    if argument.kind() == "identifier" {
                        let var_name = ast_utils::get_node_text_owned(&argument, source);
                        return self.string_literal_vars.contains(&var_name);
                    }
                }
            }
        }
        false
    }

    /// Check if strrchr/strchr is called on a const char* parameter
    fn is_search_result_of_const_param(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = ast_utils::get_node_text_owned(&function, source);
                if is_string_search_function(&func_name) {
                    // Check first argument for const char* parameter
                    if let Some(arguments) = node.child_by_field_name("arguments") {
                        for i in 0..arguments.child_count() {
                            if let Some(arg) = arguments.child(i) {
                                if arg.kind() != "," && arg.kind() != "(" && arg.kind() != ")" {
                                    // First non-punctuation argument
                                    if arg.kind() == "identifier" {
                                        let arg_name = ast_utils::get_node_text_owned(&arg, source);
                                        if self.const_char_params.contains(&arg_name) {
                                            return true;
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if a function call might return a string literal
    /// Heuristic: functions named get_string, get_* returning char* are suspicious
    fn is_function_returning_literal(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = ast_utils::get_node_text_owned(&function, source);
                // Heuristic: functions with "get" or "string" in name might return literals
                let func_lower = func_name.to_lowercase();
                if func_lower.contains("get_string")
                    || func_lower.contains("getstring")
                    || func_lower == "get_name"
                    || func_lower == "getname"
                {
                    return true;
                }
            }
        }
        false
    }

    /// Check if an initializer list contains string literals
    fn initializer_contains_string_literal(&self, node: &Node, source: &str) -> bool {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "string_literal" {
                    return true;
                }
                if child.kind() == "initializer_list" {
                    if self.initializer_contains_string_literal(&child, source) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if value is result of a string search function on a literal
    fn is_search_result_of_literal(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = ast_utils::get_node_text_owned(&function, source);
                if is_string_search_function(&func_name) {
                    // Check first argument for string literal
                    if let Some(arguments) = node.child_by_field_name("arguments") {
                        for i in 0..arguments.child_count() {
                            if let Some(arg) = arguments.child(i) {
                                if arg.kind() != "," && arg.kind() != "(" && arg.kind() != ")" {
                                    // First non-punctuation argument
                                    if self.is_string_literal(&arg, source) {
                                        return true;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if value is a cast from a tracked string literal variable
    fn is_cast_from_literal_var(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "cast_expression" {
            // Check the value being cast
            if let Some(value) = node.child_by_field_name("value") {
                if value.kind() == "identifier" {
                    let var_name = ast_utils::get_node_text_owned(&value, source);
                    return self.string_literal_vars.contains(&var_name);
                }
            }
        }
        false
    }

    fn is_array_declarator(&self, declarator: &Node) -> bool {
        match declarator.kind() {
            "array_declarator" => true,
            "pointer_declarator" => {
                // Check if the child is an array declarator
                for i in 0..declarator.child_count() {
                    if let Some(child) = declarator.child(i) {
                        if self.is_array_declarator(&child) {
                            return true;
                        }
                    }
                }
                false
            }
            _ => false,
        }
    }

    fn process_assignment(
        &mut self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            // Check if assigning to a string literal element
            if left.kind() == "subscript_expression" {
                if let Some(array) = left.child(0) {
                    if self.is_string_literal(&array, source) {
                        self.flag_violation(
                            node,
                            "Attempting to modify a string literal through array subscript",
                            violations,
                        );
                    } else if array.kind() == "identifier" {
                        let var_name = ast_utils::get_node_text_owned(&array, source);
                        if self.string_literal_vars.contains(&var_name) {
                            self.flag_violation(
                                node,
                                &format!(
                                    "Attempting to modify string literal through variable '{}'",
                                    var_name
                                ),
                                violations,
                            );
                        }
                    }
                }
            }

            // Check if assigning through a pointer to string literal
            if left.kind() == "pointer_expression" {
                if let Some(argument) = left.child_by_field_name("argument") {
                    if self.is_string_literal(&argument, source) {
                        self.flag_violation(
                            node,
                            "Attempting to modify a string literal through pointer dereference",
                            violations,
                        );
                    }
                }
            }

            // Track new assignments
            if left.kind() == "identifier" {
                let var_name = ast_utils::get_node_text_owned(&left, source);
                if self.is_string_literal(&right, source) {
                    self.string_literal_vars.insert(var_name);
                } else if self.is_search_result_of_literal(&right, source) {
                    // Track strrchr/strchr on string literal
                    self.string_literal_vars.insert(var_name);
                } else if self.is_search_result_of_const_param(&right, source) {
                    // Track strrchr/strchr on const char* parameter
                    self.search_result_vars.insert(var_name);
                } else {
                    // If assigning non-string-literal, remove from tracking
                    self.string_literal_vars.remove(&var_name);
                    self.search_result_vars.remove(&var_name);
                }
            }
        }
    }

    fn check_function_call(
        &mut self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let Some(function) = node.child_by_field_name("function") else {
            return;
        };
        let func_name = ast_utils::get_node_text_owned(&function, source);

        if is_string_modifying_function(&func_name) {
            self.check_string_modifying_call_dest(node, &func_name, source, violations);
        } else if !is_string_search_function(&func_name) && !is_safe_function(&func_name) {
            // Check for user-defined functions that might modify their char* argument.
            // Heuristic: If passing a string literal to a non-const char* parameter
            self.check_unknown_function_literal_arg(node, &func_name, source, violations);
        }
    }

    /// A known string-modifying function's first argument is the
    /// destination; flag it if it's a string literal or a variable known to
    /// point at one.
    fn check_string_modifying_call_dest(
        &mut self,
        node: &Node,
        func_name: &str,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        // Get the first non-punctuation argument (destination for most string functions)
        let Some(arg) = (0..arguments.child_count())
            .filter_map(|i| arguments.child(i))
            .find(|arg| !matches!(arg.kind(), "," | "(" | ")"))
        else {
            return;
        };

        if self.is_string_literal(&arg, source) {
            self.flag_violation(
                node,
                &format!("Passing string literal as destination to '{}'", func_name),
                violations,
            );
        } else if arg.kind() == "identifier" {
            let var_name = ast_utils::get_node_text_owned(&arg, source);
            if self.string_literal_vars.contains(&var_name) {
                self.flag_violation(
                    node,
                    &format!(
                        "Passing pointer to string literal as destination to '{}'",
                        func_name
                    ),
                    violations,
                );
            }
        }
    }

    /// Heuristic for unknown functions: a string literal passed to a
    /// function whose name suggests mutation (`modify`/`change`/`set`/`update`).
    fn check_unknown_function_literal_arg(
        &mut self,
        node: &Node,
        func_name: &str,
        _source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let func_lower = func_name.to_lowercase();
        let suggests_modification = func_lower.contains("modify")
            || func_lower.contains("change")
            || func_lower.contains("set")
            || func_lower.contains("update");
        if !suggests_modification {
            return;
        }
        for i in 0..arguments.child_count() {
            let Some(arg) = arguments.child(i) else {
                continue;
            };
            if arg.kind() == "string_literal" {
                self.flag_violation(
                    node,
                    &format!(
                        "Passing string literal to function '{}' which may modify it",
                        func_name
                    ),
                    violations,
                );
            }
        }
    }

    fn check_array_modification(
        &mut self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check if this subscript expression is on the left side of an assignment
        let Some(parent) = node.parent() else { return };
        if parent.kind() != "assignment_expression" {
            return;
        }
        let Some(left) = parent.child_by_field_name("left") else {
            return;
        };
        if left.byte_range() != node.byte_range() {
            return;
        }
        // This subscript is being assigned to
        let Some(array) = node.child(0) else { return };

        if self.is_string_literal(&array, source) {
            self.flag_violation(
                node,
                "Attempting to modify a string literal through array subscript",
                violations,
            );
            return;
        }
        match array.kind() {
            "identifier" => self.check_array_mod_identifier(node, &array, source, violations),
            "subscript_expression" => {
                self.check_array_mod_nested_subscript(node, &array, source, violations)
            }
            "field_expression" => {
                self.check_array_mod_field_expression(node, &array, source, violations)
            }
            "parenthesized_expression" => {
                self.check_array_mod_paren_deref(node, &array, source, violations)
            }
            _ => {}
        }
    }

    /// `arr[i] = ...` where `arr` is a bare identifier: flag if it's a known
    /// string-literal variable or a search-result variable that may point
    /// at one.
    fn check_array_mod_identifier(
        &mut self,
        node: &Node,
        array: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let var_name = ast_utils::get_node_text_owned(array, source);
        if self.string_literal_vars.contains(&var_name) {
            self.flag_violation(
                node,
                &format!(
                    "Attempting to modify string literal through variable '{}'",
                    var_name
                ),
                violations,
            );
        }
        if self.search_result_vars.contains(&var_name) {
            self.flag_violation(
                node,
                &format!(
                    "Attempting to modify through '{}' which may point to a string literal",
                    var_name
                ),
                violations,
            );
        }
    }

    /// Double subscript like `strings[1][0] = ...`: check the base array.
    fn check_array_mod_nested_subscript(
        &mut self,
        node: &Node,
        array: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let Some(base) = array.child(0) else { return };
        if base.kind() != "identifier" {
            return;
        }
        let var_name = ast_utils::get_node_text_owned(&base, source);
        if self.string_literal_vars.contains(&var_name) {
            self.flag_violation(
                node,
                &format!(
                    "Attempting to modify string literal through array '{}'",
                    var_name
                ),
                violations,
            );
        }
    }

    /// Struct member access like `d.name[0] = ...`: check the struct variable.
    fn check_array_mod_field_expression(
        &mut self,
        node: &Node,
        array: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let Some(argument) = array.child_by_field_name("argument") else {
            return;
        };
        let struct_name = ast_utils::get_node_text_owned(&argument, source);
        // Check if this struct was initialized with string literals
        if self.string_literal_vars.contains(&struct_name) {
            self.flag_violation(
                node,
                &format!(
                    "Attempting to modify string literal through struct member in '{}'",
                    struct_name
                ),
                violations,
            );
        }
    }

    /// Pattern `(*ptr)[n] = ...` where `ptr` is a double pointer.
    fn check_array_mod_paren_deref(
        &mut self,
        node: &Node,
        array: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let Some(deref_var) = self.extract_deref_var_from_paren(array, source) else {
            return;
        };
        if self.double_pointer_vars.contains(&deref_var) {
            self.flag_violation(
                node,
                &format!(
                    "Attempting to modify string literal through double pointer '{}'",
                    deref_var
                ),
                violations,
            );
        }
    }

    /// Extract variable name from (*ptr) pattern in parenthesized expression
    fn extract_deref_var_from_paren(&self, node: &Node, source: &str) -> Option<String> {
        // Look for pointer_expression inside the parentheses
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "pointer_expression" {
                    // Check if this is a dereference (*)
                    let expr_text = ast_utils::get_node_text_owned(&child, source);
                    if expr_text.starts_with('*') {
                        if let Some(argument) = child.child_by_field_name("argument") {
                            if argument.kind() == "identifier" {
                                return Some(ast_utils::get_node_text_owned(&argument, source));
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn check_pointer_modification(
        &mut self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check if this pointer expression is on the left side of an assignment
        if let Some(parent) = node.parent() {
            if parent.kind() == "assignment_expression" {
                if let Some(left) = parent.child_by_field_name("left") {
                    if left.byte_range() == node.byte_range() {
                        // This pointer dereference is being assigned to
                        if let Some(argument) = node.child_by_field_name("argument") {
                            if self.is_string_literal(&argument, source) {
                                self.flag_violation(
                                    node,
                                    "Attempting to modify a string literal through pointer dereference",
                                    violations,
                                );
                            } else if argument.kind() == "identifier" {
                                let var_name = ast_utils::get_node_text_owned(&argument, source);
                                if self.string_literal_vars.contains(&var_name) {
                                    self.flag_violation(
                                        node,
                                        &format!(
                                            "Attempting to modify string literal through pointer '{}'",
                                            var_name
                                        ),
                                        violations,
                                    );
                                }
                                // Check if this is a search result var (e.g., strrchr result)
                                if self.search_result_vars.contains(&var_name) {
                                    self.flag_violation(
                                        node,
                                        &format!(
                                            "Attempting to modify string through '{}' which may point to a string literal",
                                            var_name
                                        ),
                                        violations,
                                    );
                                }
                            } else if argument.kind() == "subscript_expression" {
                                // Handle (*ptr)[n] pattern - dereference of double pointer
                                // We need to detect *ptr where ptr is a double pointer to literal
                                // Actually this is subscript on deref, handled differently
                            }
                        }
                    }
                }
            }
        }
    }

    fn is_string_literal(&self, node: &Node, source: &str) -> bool {
        match node.kind() {
            "string_literal" | "concatenated_string" => true,
            "cast_expression" => {
                // Check if casting a string literal
                if let Some(value) = node.child_by_field_name("value") {
                    self.is_string_literal(&value, source)
                } else {
                    false
                }
            }
            "identifier" => {
                // Check for predefined macros that expand to string literals
                let text = ast_utils::get_node_text_owned(node, source);
                matches!(
                    text.as_str(),
                    "__FILE__" | "__func__" | "__FUNCTION__" | "__PRETTY_FUNCTION__"
                )
            }
            "conditional_expression" => {
                // Ternary expression: condition ? consequent : alternative
                // If either branch is a string literal, the result may be a string literal
                if let Some(consequent) = node.child_by_field_name("consequence") {
                    if self.is_string_literal(&consequent, source) {
                        return true;
                    }
                }
                if let Some(alternative) = node.child_by_field_name("alternative") {
                    if self.is_string_literal(&alternative, source) {
                        return true;
                    }
                }
                false
            }
            "parenthesized_expression" => {
                // Check inside parentheses
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() != "(" && child.kind() != ")" {
                            if self.is_string_literal(&child, source) {
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

    /// Resolve a declarator's bound identifier, unwrapping arbitrarily-nested
    /// pointer/array/function/parenthesized declarators (see
    /// `ast_utils::get_identifier_from_declarator`). Returns `"unknown"`
    /// (this rule's existing not-found sentinel) instead of an empty string.
    fn get_variable_name(&self, declarator: &Node, source: &str) -> String {
        match ast_utils::get_identifier_from_declarator(declarator, source) {
            name if name.is_empty() => "unknown".to_string(),
            name => name,
        }
    }

    fn flag_violation(&self, node: &Node, message: &str, violations: &mut Vec<RuleViolation>) {
        let start_point = node.start_position();
        violations.push(RuleViolation {
            rule_id: "STR30-C".to_string(),
            severity: Severity::High,
            message: message.to_string(),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some("Use a modifiable array instead of a string literal".to_string()),
            ..Default::default()
        });
    }
}

fn is_string_modifying_function(func_name: &str) -> bool {
    matches!(
        func_name,
        "strcpy"
            | "strncpy"
            | "strcat"
            | "strncat"
            | "sprintf"
            | "snprintf"
            | "vsprintf"
            | "vsnprintf"
            | "gets"
            | "fgets"
            | "scanf"
            | "fscanf"
            | "sscanf"
            | "strtok"
            | "memcpy"
            | "memmove"
            | "memset"
            | "bcopy"
            | "bzero"
            | "mkstemp"   // POSIX function that modifies template string
            | "mkdtemp" // Similar to mkstemp
    )
}

/// Functions that return a pointer into their string argument
fn is_string_search_function(func_name: &str) -> bool {
    matches!(
        func_name,
        "strchr" | "strrchr" | "strstr" | "strpbrk" | "memchr"
    )
}

/// Functions that are safe and don't modify their arguments
fn is_safe_function(func_name: &str) -> bool {
    matches!(
        func_name,
        "printf"
            | "fprintf"
            | "sprintf"
            | "snprintf"
            | "puts"
            | "fputs"
            | "strlen"
            | "strcmp"
            | "strncmp"
            | "strcasecmp"
            | "strncasecmp"
            | "atoi"
            | "atol"
            | "atof"
            | "strtol"
            | "strtoul"
            | "strtod"
            | "main"
            | "exit"
            | "abort"
    )
}
