use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Arr37C;

impl CertRule for Arr37C {
    fn rule_id(&self) -> &'static str {
        "ARR37-C"
    }

    fn description(&self) -> &'static str {
        "Do not add or subtract an integer to a pointer to a non-array object"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ARR37-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // File-scope (outside any function) declarations/assignments form a
        // base map visible to every function. Scoped strictly to nodes with
        // no enclosing function so a global's type never gets shadowed by
        // some unrelated function's local of the same name.
        let mut global_analyzer = NonArrayPointerAnalyzer::new();
        for decl in query::find_descendants_of_kind(*node, "declaration") {
            if ast_utils::find_containing_function(&decl).is_none() {
                global_analyzer.process_declaration(&decl, source);
            }
        }
        for assign in query::find_descendants_of_kind(*node, "assignment_expression") {
            if ast_utils::find_containing_function(&assign).is_none() {
                global_analyzer.process_assignment(&assign, source);
            }
        }

        // Check any file-scope code (rare) using only the global map, and
        // only for nodes that aren't inside a function (those are handled
        // per-function below).
        self.check_node_filtered(node, source, &global_analyzer, &mut violations, &|n| {
            ast_utils::find_containing_function(n).is_none()
        });

        // Analyze each function independently: a fresh variable-type map per
        // function (seeded with the file-scope globals) so that two
        // functions with a same-named local of different types are never
        // conflated into one global entry.
        for function in query::find_descendants_of_kind(*node, "function_definition") {
            let mut analyzer = NonArrayPointerAnalyzer::new();
            analyzer.variable_types = global_analyzer.variable_types.clone();
            analyzer.struct_member_pointers = global_analyzer.struct_member_pointers.clone();

            // Collect this function's own declarations/assignments/params.
            analyzer.collect_variable_info(&function, source);

            // Check for violations within this function only.
            self.check_node(&function, source, &analyzer, &mut violations);
        }

        violations
    }
}

impl Arr37C {
    fn check_node(
        &self,
        node: &Node,
        source: &str,
        analyzer: &NonArrayPointerAnalyzer,
        violations: &mut Vec<RuleViolation>,
    ) {
        self.check_node_filtered(node, source, analyzer, violations, &|_| true);
    }

    fn check_node_filtered(
        &self,
        node: &Node,
        source: &str,
        analyzer: &NonArrayPointerAnalyzer,
        violations: &mut Vec<RuleViolation>,
        filter: &dyn Fn(&Node) -> bool,
    ) {
        let matches = query::find_descendants_of_kinds(
            *node,
            &[
                "binary_expression",
                "update_expression",
                "assignment_expression",
                "subscript_expression",
                "for_statement",
            ],
        );
        for n in matches {
            if !filter(&n) {
                continue;
            }
            let node_text = &source[n.start_byte()..n.end_byte()];

            match n.kind() {
                "binary_expression" => {
                    self.check_pointer_arithmetic(&n, source, analyzer, violations);
                }
                "update_expression" => {
                    self.check_pointer_increment_decrement(&n, source, analyzer, violations);
                }
                "assignment_expression"
                    // Check if this is a compound assignment (+=, -=)
                    if (node_text.contains("+=") || node_text.contains("-=")) => {
                        self.check_compound_assignment(&n, source, analyzer, violations);
                    }
                "subscript_expression" => {
                    self.check_subscript_on_non_array(&n, source, analyzer, violations);
                }
                "for_statement" => {
                    self.check_for_loop_pointer_arithmetic(&n, source, analyzer, violations);
                }
                _ => {}
            }
        }
    }

    fn check_pointer_arithmetic(
        &self,
        node: &Node,
        source: &str,
        analyzer: &NonArrayPointerAnalyzer,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(operator) = get_operator(node, source) {
            match operator.as_str() {
                "+" | "-" => {
                    if let (Some(left), Some(right)) = (
                        node.child_by_field_name("left"),
                        node.child_by_field_name("right"),
                    ) {
                        // Check if this is pointer arithmetic (pointer +/- integer)
                        if self.is_pointer_arithmetic(&left, &right, source, analyzer) {
                            let pointer_name = self.get_pointer_name(&left, source);

                            // ARR37-C-EX1: "Any non-array object in memory
                            // can be considered an array consisting of one
                            // element." A non-array pointer plus exactly 1
                            // computes the well-defined one-past-the-end
                            // address (e.g. the classic malloc(sizeof(T) +
                            // extra) trailing-allocation idiom) — only
                            // applies to `+`, not `-`, and only offset 1.
                            let is_ex1_offset =
                                operator.as_str() == "+" && is_literal_one(&right, source);

                            // Skip ambiguous parameters and unknown pointers - can't determine statically
                            if analyzer.is_ambiguous_parameter(&pointer_name)
                                || analyzer.is_unknown_pointer(&pointer_name)
                            {
                                // Don't flag - could be arrays or single objects
                            } else if analyzer.is_trailing_allocation_pointer(&pointer_name)
                                && is_ex1_offset
                            {
                                // ARR37-C-EX1 applies
                            } else if analyzer.is_struct_member_pointer(&pointer_name) {
                                let start_point = node.start_position();
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::Critical,
                                    message: format!(
                                        "Pointer arithmetic on struct member pointer '{}'. Pointer arithmetic on struct members is undefined behavior",
                                        pointer_name
                                    ),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some("Do not perform pointer arithmetic across struct members".to_string()),
                                    ..Default::default()
                                });
                            } else if analyzer.is_non_array_pointer(&pointer_name) {
                                let start_point = node.start_position();
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::High,
                                    message: format!(
                                        "Pointer arithmetic on non-array pointer '{}'. Only perform arithmetic on array pointers",
                                        pointer_name
                                    ),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some("Use array indexing or ensure pointer refers to an array".to_string()),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn check_pointer_increment_decrement(
        &self,
        node: &Node,
        source: &str,
        analyzer: &NonArrayPointerAnalyzer,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(argument) = node.child_by_field_name("argument") {
            let pointer_name = self.get_pointer_name(&argument, source);
            let start_point = node.start_position();
            let op_text = &source[node.start_byte()..node.end_byte()];

            // ARR37-C-EX1: `ptr++`/`++ptr` on a non-array pointer computes
            // the well-defined one-past-the-end address (offset exactly
            // 1) — `ptr--`/`--ptr` is not covered (goes out of bounds).
            let is_ex1_offset = op_text.contains("++");

            // Skip ambiguous parameters and unknown pointers - can't determine statically
            if analyzer.is_ambiguous_parameter(&pointer_name)
                || analyzer.is_unknown_pointer(&pointer_name)
            {
                // Don't flag - could be arrays or single objects
            } else if analyzer.is_trailing_allocation_pointer(&pointer_name) && is_ex1_offset {
                // ARR37-C-EX1 applies
            } else if analyzer.is_struct_member_pointer(&pointer_name) {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Critical,
                    message: format!(
                        "Increment/decrement operation '{}' on struct member pointer '{}'. Pointer arithmetic on struct members is undefined behavior",
                        op_text, pointer_name
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Do not perform pointer arithmetic across struct members".to_string()),
                    ..Default::default()
                });
            } else if analyzer.is_non_array_pointer(&pointer_name) {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Increment/decrement operation '{}' on non-array pointer '{}'",
                        op_text, pointer_name
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(
                        "Use array indexing or ensure pointer refers to an array".to_string(),
                    ),
                    ..Default::default()
                });
            }
        }
    }

    fn check_compound_assignment(
        &self,
        node: &Node,
        source: &str,
        analyzer: &NonArrayPointerAnalyzer,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check for patterns like: ptr += n, ptr -= n
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            // Get the operator
            let full_text = &source[node.start_byte()..node.end_byte()];
            if full_text.contains("+=") || full_text.contains("-=") {
                let pointer_name = self.get_pointer_name(&left, source);
                let start_point = node.start_position();
                let op_text = &source[node.start_byte()..node.end_byte()];

                // ARR37-C-EX1: `ptr += 1` on a non-array pointer computes
                // the well-defined one-past-the-end address.
                let is_ex1_offset = full_text.contains("+=") && is_literal_one(&right, source);

                // Skip ambiguous parameters and unknown pointers - can't determine statically
                if analyzer.is_ambiguous_parameter(&pointer_name)
                    || analyzer.is_unknown_pointer(&pointer_name)
                {
                    // Don't flag - could be arrays or single objects
                } else if analyzer.is_trailing_allocation_pointer(&pointer_name) && is_ex1_offset {
                    // ARR37-C-EX1 applies
                } else if analyzer.is_struct_member_pointer(&pointer_name) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Critical,
                        message: format!(
                            "Compound assignment '{}' on struct member pointer '{}'. Pointer arithmetic on struct members is undefined behavior",
                            op_text, pointer_name
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Do not perform pointer arithmetic across struct members".to_string()),
                        ..Default::default()
                    });
                } else if analyzer.is_non_array_pointer(&pointer_name) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Compound assignment '{}' on non-array pointer '{}'",
                            op_text, pointer_name
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Use array indexing or ensure pointer refers to an array".to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    fn check_subscript_on_non_array(
        &self,
        node: &Node,
        source: &str,
        analyzer: &NonArrayPointerAnalyzer,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check for patterns like: ptr[index] where ptr is not an array pointer
        // subscript_expression has "argument" (the base pointer/array) and "index" fields
        if let Some(argument) = node.child_by_field_name("argument") {
            let pointer_name = self.get_pointer_name(&argument, source);

            // Only check if we have a named variable (not an expression)
            if pointer_name != "unknown" && !pointer_name.is_empty() {
                let start_point = node.start_position();
                let subscript_text = &source[node.start_byte()..node.end_byte()];

                // Skip ambiguous parameters and unknown pointers - can't determine statically
                if analyzer.is_ambiguous_parameter(&pointer_name)
                    || analyzer.is_unknown_pointer(&pointer_name)
                {
                    // Don't flag - could be arrays or single objects
                } else if analyzer.is_struct_member_pointer(&pointer_name) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Critical,
                        message: format!(
                            "Subscript operation '{}' on struct member pointer '{}'. Pointer arithmetic on struct members is undefined behavior",
                            subscript_text, pointer_name
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Do not perform pointer arithmetic across struct members".to_string()),
                        ..Default::default()
                    });
                } else if analyzer.is_non_array_pointer(&pointer_name) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Subscript operation '{}' on non-array pointer '{}'. Subscript notation implies array access",
                            subscript_text, pointer_name
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Only use subscript notation on array pointers, not pointers to single objects".to_string()),
                        ..Default::default()
                    });
                }
            }
        }
    }

    fn check_for_loop_pointer_arithmetic(
        &self,
        node: &Node,
        source: &str,
        analyzer: &NonArrayPointerAnalyzer,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check for patterns like: for (ptr = &struct.member; ptr <= &struct.other_member; ptr++)
        if let Some(update) = node.child_by_field_name("update") {
            if update.kind() == "update_expression" {
                if let Some(argument) = update.child_by_field_name("argument") {
                    let pointer_name = self.get_pointer_name(&argument, source);

                    // Check if this pointer is being used to iterate over struct members
                    if analyzer.is_struct_member_pointer(&pointer_name) {
                        let start_point = node.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Critical,
                            message: format!(
                                "Pointer arithmetic in loop on struct member pointer '{}'. Structure members are not guaranteed to be contiguous",
                                pointer_name
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some("Access struct members individually or use an array within the struct".to_string()),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    fn is_pointer_arithmetic(
        &self,
        left: &Node,
        right: &Node,
        source: &str,
        analyzer: &NonArrayPointerAnalyzer,
    ) -> bool {
        let left_text = &source[left.start_byte()..left.end_byte()];
        let right_text = &source[right.start_byte()..right.end_byte()];

        // Check if left is a pointer and right is an integer
        // Only consider it pointer arithmetic if the left side is actually a known pointer variable
        let left_is_pointer =
            left.kind() == "identifier" && analyzer.is_pointer_variable(left_text);
        let right_is_integer =
            right_text.chars().all(|c| c.is_ascii_digit()) || right.kind() == "number_literal";

        left_is_pointer && right_is_integer
    }

    fn get_pointer_name(&self, node: &Node, source: &str) -> String {
        match node.kind() {
            "identifier" => source[node.start_byte()..node.end_byte()].to_string(),
            _ => "unknown".to_string(),
        }
    }
}

struct NonArrayPointerAnalyzer {
    // Maps variable names to their types (array, non-array, struct-member-pointer)
    variable_types: HashMap<String, VariableType>,
    // Tracks struct member pointers
    struct_member_pointers: HashMap<String, String>,
}

#[derive(Debug, Clone)]
enum VariableType {
    Array,
    NonArray,
    // A non-array pointer from `malloc(sizeof(T) + extra)` — the classic
    // flexible-trailing-allocation idiom. ARR37-C-EX1 permits exactly a
    // `+1` offset on this pointer (the well-defined one-past-the-end
    // address used to reach the trailing bytes); anything else is still a
    // violation. Kept distinct from plain NonArray (e.g. `&stack_var`) so
    // EX1 doesn't blanket-exempt ordinary single-object pointer misuse.
    TrailingAllocation,
    StructMemberPointer,
    AmbiguousParameter,
    Unknown,
}

impl NonArrayPointerAnalyzer {
    fn new() -> Self {
        Self {
            variable_types: HashMap::new(),
            struct_member_pointers: HashMap::new(),
        }
    }

    fn collect_variable_info(&mut self, node: &Node, source: &str) {
        let matches = query::find_descendants_of_kinds(
            *node,
            &[
                "declaration",
                "assignment_expression",
                "function_definition",
            ],
        );
        for n in matches {
            match n.kind() {
                "declaration" => {
                    self.process_declaration(&n, source);
                }
                "assignment_expression" => {
                    self.process_assignment(&n, source);
                }
                "function_definition" => {
                    self.process_function_definition(&n, source);
                }
                _ => {}
            }
        }
    }

    fn process_declaration(&mut self, node: &Node, source: &str) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(declarator) = child.child_by_field_name("declarator") {
                        let var_name =
                            ast_utils::get_identifier_from_declarator(&declarator, source);

                        // Determine if this is an array or pointer declaration
                        // Only track arrays and pointers - skip non-pointer variables entirely
                        let var_type = if declarator.kind() == "array_declarator" {
                            // Check if this is a VLA (variable length array)
                            // VLAs have non-constant size expressions
                            Some(VariableType::Array)
                        } else if declarator.kind() == "pointer_declarator" {
                            // Check if initialized with array reference
                            if let Some(value) = child.child_by_field_name("value") {
                                Some(self.analyze_initializer_type(&value, source))
                            } else {
                                Some(VariableType::Unknown)
                            }
                        } else {
                            None // Not a pointer or array, skip it
                        };

                        if !var_name.is_empty() {
                            if let Some(var_type) = var_type {
                                self.variable_types.insert(var_name, var_type);
                            }
                        }
                    }
                } else if child.kind() == "declarator"
                    || child.kind() == "array_declarator"
                    || child.kind() == "pointer_declarator"
                {
                    // Handle declarations without initializers (e.g., int vla[n];)
                    let var_name = ast_utils::get_identifier_from_declarator(&child, source);

                    if !var_name.is_empty() {
                        let var_type = if child.kind() == "array_declarator" {
                            Some(VariableType::Array)
                        } else if child.kind() == "pointer_declarator" {
                            Some(VariableType::Unknown)
                        } else {
                            None
                        };

                        if let Some(var_type) = var_type {
                            self.variable_types.insert(var_name, var_type);
                        }
                    }
                }
            }
        }
    }

    fn process_assignment(&mut self, node: &Node, source: &str) {
        // Skip compound assignments (+=, -=, etc.) as they don't change the pointer type
        let node_text = &source[node.start_byte()..node.end_byte()];
        if node_text.contains("+=")
            || node_text.contains("-=")
            || node_text.contains("*=")
            || node_text.contains("/=")
        {
            return;
        }

        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            if left.kind() == "identifier" {
                let var_name = source[left.start_byte()..left.end_byte()].to_string();

                // Skip binary expressions (like ptr = ptr + 1) as they don't change the pointer type
                // The actual pointer arithmetic will be caught by check_pointer_arithmetic
                if right.kind() == "binary_expression" {
                    return;
                }

                let var_type = self.analyze_initializer_type(&right, source);
                self.variable_types.insert(var_name.clone(), var_type);

                // Check for struct member pointer assignment
                if right.kind() == "unary_expression" {
                    if let Some(argument) = right.child_by_field_name("argument") {
                        if argument.kind() == "field_expression" {
                            self.struct_member_pointers
                                .insert(var_name, "struct_member".to_string());
                        }
                    }
                }
            }
        }
    }

    fn process_function_definition(&mut self, node: &Node, source: &str) {
        // Get the parameter list - don't recurse, parent handles that
        if let Some(declarator) = node.child_by_field_name("declarator") {
            if let Some(parameters) = declarator.child_by_field_name("parameters") {
                let mut pointer_params = Vec::new();

                for i in 0..parameters.child_count() {
                    if let Some(param) = parameters.child(i) {
                        if param.kind() == "parameter_declaration" {
                            if let Some(param_declarator) = param.child_by_field_name("declarator")
                            {
                                let param_name = ast_utils::get_identifier_from_declarator(
                                    &param_declarator,
                                    source,
                                );

                                if !param_name.is_empty() {
                                    if param_declarator.kind() == "array_declarator" {
                                        // Parameter declared as array (e.g., int param[])
                                        self.variable_types.insert(param_name, VariableType::Array);
                                    } else if param_declarator.kind() == "pointer_declarator" {
                                        pointer_params.push(param_name);
                                    }
                                }
                            }
                        }
                    }
                }

                // All pointer parameters are ambiguous — can't determine statically
                // whether they point to arrays or single objects
                for param_name in pointer_params {
                    self.variable_types
                        .insert(param_name, VariableType::AmbiguousParameter);
                }
            }
        }
    }

    fn analyze_initializer_type(&self, node: &Node, source: &str) -> VariableType {
        match node.kind() {
            "identifier" => {
                // Check if it's an array name
                let name = source[node.start_byte()..node.end_byte()].to_string();
                if let Some(existing_type) = self.variable_types.get(&name) {
                    existing_type.clone()
                } else {
                    VariableType::Unknown
                }
            }
            "unary_expression" | "pointer_expression" => {
                // Handle &array, &variable patterns
                // pointer_expression is used by tree-sitter for address-of operations
                if let Some(argument) = node.child_by_field_name("argument") {
                    match argument.kind() {
                        "identifier" => VariableType::NonArray,           // &variable
                        "subscript_expression" => VariableType::NonArray, // &array[0] is pointer to single element
                        "field_expression" => VariableType::StructMemberPointer, // &struct.member
                        _ => VariableType::Unknown,
                    }
                } else {
                    VariableType::Unknown
                }
            }
            "subscript_expression" => VariableType::Array,
            "cast_expression" => {
                // For cast expressions, check what's being cast
                // e.g., (double *)calloc(...) should be recognized as Array
                if let Some(value) = node.child_by_field_name("value") {
                    self.analyze_initializer_type(&value, source)
                } else {
                    VariableType::NonArray
                }
            }
            "call_expression" => {
                // Check for malloc/calloc/realloc patterns
                self.analyze_allocation_call(node, source)
            }
            _ => VariableType::Unknown,
        }
    }

    fn analyze_allocation_call(&self, node: &Node, source: &str) -> VariableType {
        // Get function name
        if let Some(function) = node.child_by_field_name("function") {
            let func_name = source[function.start_byte()..function.end_byte()].to_string();

            match func_name.as_str() {
                "malloc" | "realloc" => {
                    // malloc(sizeof(T)) -> NonArray (single object)
                    // malloc(N * sizeof(T)) -> Array
                    // malloc(sizeof(T) + extra) -> TrailingAllocation
                    // (ARR37-C-EX1 flexible trailing-allocation idiom)
                    if let Some(arguments) = node.child_by_field_name("arguments") {
                        let arg_text =
                            source[arguments.start_byte()..arguments.end_byte()].to_string();
                        // If there's multiplication or multiple sizeof calls, it's an array
                        if arg_text.contains('*') {
                            VariableType::Array
                        } else if arg_text.contains("sizeof") && arg_text.contains('+') {
                            VariableType::TrailingAllocation
                        } else {
                            // Single sizeof -> single object
                            VariableType::NonArray
                        }
                    } else {
                        VariableType::NonArray
                    }
                }
                "calloc" => {
                    // calloc(N, sizeof(T)) -> treat as Array unless N==1
                    if let Some(arguments) = node.child_by_field_name("arguments") {
                        let arg_text =
                            source[arguments.start_byte()..arguments.end_byte()].to_string();
                        // Remove parentheses and split by comma
                        let cleaned = arg_text.trim_matches(&['(', ')', ' '][..]);
                        let args: Vec<&str> = cleaned.split(',').map(|s| s.trim()).collect();
                        // If first arg is 1, it's a single object allocation
                        if !args.is_empty() && args[0] == "1" {
                            VariableType::NonArray
                        } else {
                            // Otherwise it's an array
                            VariableType::Array
                        }
                    } else {
                        VariableType::Array
                    }
                }
                // Stack allocation functions always allocate arrays
                "alloca" | "ALLOCA" | "_alloca" | "_malloca" => VariableType::Array,
                // aligned_alloc(alignment, size) — same pattern as malloc
                "aligned_alloc" => {
                    if let Some(arguments) = node.child_by_field_name("arguments") {
                        let arg_text =
                            source[arguments.start_byte()..arguments.end_byte()].to_string();
                        if arg_text.contains('*') {
                            VariableType::Array
                        } else {
                            VariableType::NonArray
                        }
                    } else {
                        VariableType::NonArray
                    }
                }
                _ => VariableType::Unknown,
            }
        } else {
            VariableType::Unknown
        }
    }

    fn is_non_array_pointer(&self, var_name: &str) -> bool {
        matches!(
            self.variable_types.get(var_name),
            Some(VariableType::NonArray) | Some(VariableType::TrailingAllocation)
        )
    }

    fn is_trailing_allocation_pointer(&self, var_name: &str) -> bool {
        matches!(
            self.variable_types.get(var_name),
            Some(VariableType::TrailingAllocation)
        )
    }

    fn is_struct_member_pointer(&self, var_name: &str) -> bool {
        self.struct_member_pointers.contains_key(var_name)
            || matches!(
                self.variable_types.get(var_name),
                Some(VariableType::StructMemberPointer)
            )
    }

    fn is_ambiguous_parameter(&self, var_name: &str) -> bool {
        matches!(
            self.variable_types.get(var_name),
            Some(VariableType::AmbiguousParameter)
        )
    }

    fn is_unknown_pointer(&self, var_name: &str) -> bool {
        matches!(
            self.variable_types.get(var_name),
            Some(VariableType::Unknown)
        )
    }

    fn is_pointer_variable(&self, var_name: &str) -> bool {
        self.variable_types.contains_key(var_name)
    }
}

/// True if `node` is the integer literal `1` (used for ARR37-C-EX1: a
/// non-array pointer plus exactly one element is well-defined).
fn is_literal_one(node: &Node, source: &str) -> bool {
    node.kind() == "number_literal" && source[node.start_byte()..node.end_byte()].trim() == "1"
}

fn get_operator(node: &Node, source: &str) -> Option<String> {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            let text = source[child.start_byte()..child.end_byte()].to_string();
            if matches!(text.as_str(), "+" | "-") {
                return Some(text);
            }
        }
    }
    None
}
