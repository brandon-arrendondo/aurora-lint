use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Arr36C;

impl CertRule for Arr36C {
    fn rule_id(&self) -> &'static str {
        "ARR36-C"
    }

    fn description(&self) -> &'static str {
        "Do not subtract or compare two pointers that do not refer to the same array"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ARR36-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Per-function analysis: create a fresh PointerAnalyzer for each function
        // to avoid cross-function variable name collisions.
        self.visit_functions(node, source, &mut violations);

        violations
    }
}

impl Arr36C {
    /// Walk the AST to find function_definition nodes, then analyze each independently.
    /// File-scope declarations (globals) are collected first and shared across all functions.
    fn visit_functions(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // First pass: collect file-scope declarations (global arrays, static vars)
        let mut file_scope = PointerAnalyzer::new();
        file_scope.collect_file_scope(node, source);

        // Second pass: per-function analysis with file-scope as base
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            let mut analyzer = PointerAnalyzer::from(&file_scope);
            analyzer.collect_declarations(&func, source);
            self.check_node(&func, source, &analyzer, violations);
        }
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        analyzer: &PointerAnalyzer,
        violations: &mut Vec<RuleViolation>,
    ) {
        for binary_expr in query::find_descendants_of_kind(*node, "binary_expression") {
            self.check_binary_expression(&binary_expr, source, analyzer, violations);
        }
    }

    fn check_binary_expression(
        &self,
        node: &Node,
        source: &str,
        analyzer: &PointerAnalyzer,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(operator) = get_operator(node, source) {
            match operator.as_str() {
                "-" => {
                    self.check_pointer_subtraction(node, source, analyzer, violations);
                }
                "<" | "<=" | ">" | ">=" => {
                    self.check_pointer_comparison(node, source, analyzer, violations);
                }
                _ => {}
            }
        }
    }

    fn check_pointer_subtraction(
        &self,
        node: &Node,
        source: &str,
        analyzer: &PointerAnalyzer,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let left_info = analyzer.get_pointer_info(&left, source);
            let right_info = analyzer.get_pointer_info(&right, source);

            if let (Some(left_array), Some(right_array)) = (left_info, right_info) {
                if left_array != right_array {
                    let start_point = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Pointer subtraction between pointers from different arrays: '{}' and '{}'",
                            left_array, right_array
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Ensure both pointers refer to the same array before subtraction".to_string()),
                        ..Default::default()
                    });
                }
            }
        }
    }

    fn check_pointer_comparison(
        &self,
        node: &Node,
        source: &str,
        analyzer: &PointerAnalyzer,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let left_info = analyzer.get_pointer_info(&left, source);
            let right_info = analyzer.get_pointer_info(&right, source);

            if let (Some(left_array), Some(right_array)) = (left_info, right_info) {
                if left_array != right_array {
                    let start_point = node.start_position();
                    let op = get_operator(node, source).unwrap_or("?".to_string());
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Pointer comparison '{}' between pointers from different arrays: '{}' and '{}'",
                            op, left_array, right_array
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Ensure both pointers refer to the same array before comparison".to_string()),
                        ..Default::default()
                    });
                }
            }
        }
    }
}

struct PointerAnalyzer {
    // Maps variable names to their array base (for tracking which array they belong to)
    variable_arrays: HashMap<String, String>,
}

impl PointerAnalyzer {
    fn new() -> Self {
        Self {
            variable_arrays: HashMap::new(),
        }
    }

    fn from(base: &PointerAnalyzer) -> Self {
        Self {
            variable_arrays: base.variable_arrays.clone(),
        }
    }

    /// Collect file-scope declarations (globals, statics at file level).
    /// Only processes direct children of translation_unit and preproc blocks.
    fn collect_file_scope(&mut self, node: &Node, source: &str) {
        match node.kind() {
            "translation_unit" | "preproc_ifdef" | "preproc_if" | "preproc_else"
            | "preproc_elif" => {
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "declaration" {
                            self.process_declaration(&child, source);
                        } else if matches!(
                            child.kind(),
                            "preproc_ifdef" | "preproc_if" | "preproc_else" | "preproc_elif"
                        ) {
                            self.collect_file_scope(&child, source);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn collect_declarations(&mut self, node: &Node, source: &str) {
        let matches = query::find_descendants_of_kinds(
            *node,
            &[
                "declaration",
                "parameter_declaration",
                "expression_statement",
            ],
        );
        for n in matches {
            match n.kind() {
                "declaration" => {
                    self.process_declaration(&n, source);
                }
                "parameter_declaration" => {
                    self.process_parameter(&n, source);
                }
                "expression_statement" => {
                    self.process_assignment(&n, source);
                }
                _ => {}
            }
        }
    }

    fn process_declaration(&mut self, node: &Node, source: &str) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let declarator = if child.kind() == "init_declarator" {
                    child.child_by_field_name("declarator")
                } else if Self::is_pointer_declarator(&child) || child.kind() == "array_declarator"
                {
                    // Bare declarations without initializer: `int nums[SIZE];`, `int *p;`
                    Some(child)
                } else {
                    None
                };
                if let Some(declarator) = declarator {
                    if !Self::is_pointer_declarator(&declarator) {
                        continue;
                    }
                    let var_name = ast_utils::get_identifier_from_declarator(&declarator, source);
                    if var_name.is_empty() {
                        continue;
                    }
                    // Array declarations create their own storage — the variable IS its own base.
                    if declarator.kind() == "array_declarator" {
                        self.variable_arrays.insert(var_name.clone(), var_name);
                        continue;
                    }
                    // Pointer with initializer: track which array it aliases
                    if child.kind() == "init_declarator" {
                        if let Some(value) = child.child_by_field_name("value") {
                            let array_base = self.extract_array_base(&value, source);
                            if !array_base.is_empty() {
                                self.variable_arrays.insert(var_name, array_base);
                            }
                        }
                    }
                    // Bare pointer declarations without initializer: not tracked
                    // (we don't know what they point to)
                }
            }
        }
    }

    /// Check if a declarator represents a pointer type (pointer_declarator or array_declarator).
    fn is_pointer_declarator(declarator: &Node) -> bool {
        matches!(declarator.kind(), "pointer_declarator" | "array_declarator")
    }

    fn process_parameter(&mut self, node: &Node, source: &str) {
        // For function parameters, only track pointer/array parameters as distinct arrays.
        // Non-pointer parameters (int, uint32_t, etc.) are scalars — comparing them
        // is not pointer comparison and should not trigger ARR36-C.
        if !self.is_pointer_or_array_parameter(node) {
            return;
        }
        if let Some(declarator) = node.child_by_field_name("declarator") {
            let param_name = ast_utils::get_identifier_from_declarator(&declarator, source);
            if !param_name.is_empty() {
                // Use the parameter name itself as the "array base" to make it unique
                // This ensures parameters are only equal to themselves
                self.variable_arrays
                    .insert(param_name.clone(), format!("param:{}", param_name));
            }
        }
    }

    /// Process simple assignment expressions like `slashPtr = strchr(string1, '/')`.
    /// Tracks variables assigned from string-search functions (strchr, strrchr,
    /// wcschr, wcsrchr) as pointing into the first argument's array.
    /// Skips compound assignments (+=, -=) since those advance a pointer within
    /// the same array rather than changing which array it points to.
    fn process_assignment(&mut self, node: &Node, source: &str) {
        // expression_statement contains an assignment_expression child
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "assignment_expression" {
                    // Skip compound assignments (+=, -=, etc.) — they advance a pointer
                    // within the same array rather than changing which array it points to.
                    // tree-sitter puts the operator as a direct child: "=", "+=", "-=", etc.
                    let mut is_simple_assign = false;
                    for j in 0..child.child_count() {
                        if let Some(op) = child.child(j) {
                            if ast_utils::get_node_text(&op, source) == "=" {
                                is_simple_assign = true;
                                break;
                            }
                        }
                    }
                    if !is_simple_assign {
                        continue;
                    }
                    if let (Some(left), Some(right)) = (
                        child.child_by_field_name("left"),
                        child.child_by_field_name("right"),
                    ) {
                        let var_name = ast_utils::get_node_text(&left, source).to_string();
                        if var_name.is_empty()
                            || !var_name.chars().all(|c| c.is_alphanumeric() || c == '_')
                        {
                            continue;
                        }
                        let array_base = self.extract_array_base(&right, source);
                        if !array_base.is_empty() {
                            self.variable_arrays.insert(var_name, array_base);
                        }
                    }
                }
            }
        }
    }

    /// Check if a parameter declaration is a pointer or array type.
    fn is_pointer_or_array_parameter(&self, param_node: &Node) -> bool {
        // Check declarator for pointer_declarator or array_declarator
        if let Some(declarator) = param_node.child_by_field_name("declarator") {
            if declarator.kind() == "pointer_declarator" || declarator.kind() == "array_declarator"
            {
                return true;
            }
            // Check children for nested pointer/array declarators
            for i in 0..declarator.child_count() {
                if let Some(child) = declarator.child(i) {
                    if child.kind() == "pointer_declarator" || child.kind() == "array_declarator" {
                        return true;
                    }
                }
            }
        }
        // Check if the type itself contains a pointer
        if let Some(type_node) = param_node.child_by_field_name("type") {
            // Abstract pointer declarators (e.g., `void *` without name)
            if type_node.kind() == "pointer_declarator" {
                return true;
            }
        }
        false
    }

    fn extract_array_base(&self, node: &Node, source: &str) -> String {
        let result = match node.kind() {
            "identifier" => {
                let name = source[node.start_byte()..node.end_byte()].to_string();
                // Follow alias chain: if this variable is already tracked, use its base.
                // This ensures `pos = buf` gives pos the same base as buf (e.g., "param:buf").
                // Untracked identifiers return the raw name — they may be typedef arrays
                // or extern variables that weren't collected.
                if let Some(base) = self.variable_arrays.get(&name) {
                    base.clone()
                } else {
                    name
                }
            }
            "field_expression" => {
                // Handle struct.member or union.member - capture full path
                // This ensures u.int_array and u.float_array are distinct
                source[node.start_byte()..node.end_byte()].to_string()
            }
            "cast_expression" => {
                // Handle cast expressions like (int *)malloc(...) - unwrap to get the underlying value
                if let Some(value) = node.child_by_field_name("value") {
                    self.extract_array_base(&value, source)
                } else {
                    String::new()
                }
            }
            "call_expression" => {
                // Check if this is a string-search function (strchr, strrchr, wcschr, wcsrchr)
                // whose return value points into the first argument
                if let Some(func_node) = node.child_by_field_name("function") {
                    let func_name = ast_utils::get_node_text(&func_node, source);
                    // Recognize standard string-search functions and common
                    // wrapper macros (os_strchr, os_strstr, etc.)
                    let canonical = func_name.strip_prefix("os_").unwrap_or(func_name);
                    if matches!(
                        canonical,
                        "strchr"
                            | "strrchr"
                            | "wcschr"
                            | "wcsrchr"
                            | "memchr"
                            | "strstr"
                            | "wcsstr"
                            | "strpbrk"
                            | "wcspbrk"
                    ) {
                        // Return value points into the first argument
                        if let Some(args) = node.child_by_field_name("arguments") {
                            // First real argument (skip '(' which is child 0)
                            for j in 0..args.child_count() {
                                if let Some(arg) = args.child(j) {
                                    if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                                        return self.extract_array_base(&arg, source);
                                    }
                                }
                            }
                        }
                    }
                    // Allocation functions create distinct objects
                    if matches!(
                        canonical,
                        "malloc" | "calloc" | "realloc" | "aligned_alloc" | "alloca"
                    ) {
                        return format!("alloc@{}", node.start_byte());
                    }
                }
                // Other calls: unknown origin — don't assign a base.
                // Assigning a unique base would cause every unknown-call pointer
                // to mismatch with everything else, producing massive FPs.
                String::new()
            }
            "compound_literal_expression" => {
                // Handle compound literals like (int[]){1, 2, 3}
                // Each compound literal creates a distinct object
                // Use byte position to make each one unique, even if they have identical content
                format!(
                    "{}@{}",
                    &source[node.start_byte()..node.end_byte()],
                    node.start_byte()
                )
            }
            "string_literal" => {
                // Handle string literals like "Hello" and "World"
                // Each string literal creates a distinct array object
                // Use byte position to make each one unique, even if they have identical text
                format!(
                    "{}@{}",
                    &source[node.start_byte()..node.end_byte()],
                    node.start_byte()
                )
            }
            "binary_expression" => {
                // Handle pointer arithmetic like arr + size or ptr - offset
                // The base array is determined by the left operand
                if let Some(left) = node.child_by_field_name("left") {
                    self.extract_array_base(&left, source)
                } else {
                    String::new()
                }
            }
            "pointer_expression" | "unary_expression" => {
                // Handle &array[0], &array, *ptr (pointer_expression is used by tree-sitter for & and *)
                // Determine if this is address-of (&) or dereference (*)
                let is_address_of = node
                    .child(0)
                    .is_some_and(|op| ast_utils::get_node_text(&op, source) == "&");
                if let Some(argument) = node.child_by_field_name("argument") {
                    match argument.kind() {
                        "identifier" => {
                            let name =
                                source[argument.start_byte()..argument.end_byte()].to_string();
                            if is_address_of {
                                // &var: the variable itself IS the array (single-element)
                                // Use its tracked base if available, otherwise use its name
                                if let Some(base) = self.variable_arrays.get(&name) {
                                    base.clone()
                                } else {
                                    name
                                }
                            } else {
                                // *ptr: follow alias chain — the result points into
                                // whatever the pointer points to
                                if let Some(base) = self.variable_arrays.get(&name) {
                                    base.clone()
                                } else {
                                    String::new()
                                }
                            }
                        }
                        "field_expression" => {
                            // Handle &struct.member
                            // Extract just the struct instance part to allow comparisons between
                            // different members of the same struct (ARR36-C-EX1)
                            if let Some(base) = argument.child_by_field_name("argument") {
                                source[base.start_byte()..base.end_byte()].to_string()
                            } else {
                                source[argument.start_byte()..argument.end_byte()].to_string()
                            }
                        }
                        "subscript_expression" => {
                            // For subscript expressions, we need to find the deepest base array
                            // This handles &matrix[i][j] by extracting "matrix" rather than "matrix[i]"
                            self.extract_deepest_base(&argument, source)
                        }
                        _ => String::new(),
                    }
                } else {
                    String::new()
                }
            }
            "subscript_expression" => {
                // Handle array subscripts like arrays[0], arrays[1]
                // Use the full expression to distinguish between different sub-arrays
                // This is important for multidimensional arrays where arrays[0] and arrays[1]
                // are different arrays even though they share the same base
                source[node.start_byte()..node.end_byte()].to_string()
            }
            _ => String::new(),
        };
        result
    }

    fn extract_deepest_base(&self, node: &Node, source: &str) -> String {
        // Recursively extract the deepest base array from nested subscript expressions
        // For matrix[i][j], this returns "matrix"
        // For matrix[i], this returns "matrix"
        match node.kind() {
            "subscript_expression" => {
                if let Some(array) = node.child_by_field_name("argument") {
                    self.extract_deepest_base(&array, source)
                } else {
                    String::new()
                }
            }
            "identifier" => source[node.start_byte()..node.end_byte()].to_string(),
            _ => String::new(),
        }
    }

    fn get_pointer_info(&self, node: &Node, source: &str) -> Option<String> {
        match node.kind() {
            "identifier" => {
                let var_name = source[node.start_byte()..node.end_byte()].to_string();
                self.variable_arrays.get(&var_name).cloned()
            }
            "cast_expression" => {
                // Handle cast expressions like (int *)ptr - unwrap to get the underlying value
                if let Some(value) = node.child_by_field_name("value") {
                    self.get_pointer_info(&value, source)
                } else {
                    None
                }
            }
            "pointer_expression" | "unary_expression" => {
                // Handle &variable and *ptr patterns
                let is_address_of = node
                    .child(0)
                    .is_some_and(|op| ast_utils::get_node_text(&op, source) == "&");
                if let Some(argument) = node.child_by_field_name("argument") {
                    match argument.kind() {
                        "identifier" => {
                            let var_name =
                                source[argument.start_byte()..argument.end_byte()].to_string();
                            if is_address_of {
                                // &var: use tracked base or the variable name itself
                                Some(
                                    self.variable_arrays
                                        .get(&var_name)
                                        .cloned()
                                        .unwrap_or(var_name),
                                )
                            } else {
                                // *ptr: follow alias chain
                                self.variable_arrays.get(&var_name).cloned()
                            }
                        }
                        "field_expression" => {
                            let field_path =
                                source[argument.start_byte()..argument.end_byte()].to_string();
                            if is_address_of {
                                Some(
                                    self.variable_arrays
                                        .get(&field_path)
                                        .cloned()
                                        .unwrap_or(field_path),
                                )
                            } else {
                                self.variable_arrays.get(&field_path).cloned()
                            }
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            }
            "field_expression" => {
                // Handle struct.member or union.member access
                // Only return info if explicitly tracked — don't assume all field
                // expressions are pointers. Untracked fields (integers, etc.)
                // should return None to avoid flagging scalar comparisons.
                let var_name = source[node.start_byte()..node.end_byte()].to_string();
                self.variable_arrays.get(&var_name).cloned()
            }
            _ => None,
        }
    }
}

fn get_operator(node: &Node, source: &str) -> Option<String> {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            let text = source[child.start_byte()..child.end_byte()].to_string();
            if matches!(text.as_str(), "-" | "<" | "<=" | ">" | ">=") {
                return Some(text);
            }
        }
    }
    None
}
