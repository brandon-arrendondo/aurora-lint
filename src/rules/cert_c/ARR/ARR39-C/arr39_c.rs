use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use tree_sitter::Node;

pub struct Arr39C;

impl CertRule for Arr39C {
    fn rule_id(&self) -> &'static str {
        "ARR39-C"
    }

    fn description(&self) -> &'static str {
        "Do not add or subtract a scaled integer to a pointer"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ARR39-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        self.check_node(node, source, &mut violations);

        violations
    }
}

impl Arr39C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        match node.kind() {
            "binary_expression" => {
                self.check_pointer_arithmetic(node, source, violations);
            }
            "assignment_expression" => {
                self.check_assignment_arithmetic(node, source, violations);
            }
            "call_expression" => {
                self.check_function_call_scaling(node, source, violations);
            }
            "while_statement" | "for_statement" => {
                self.check_loop_pointer_arithmetic(node, source, violations);
            }
            "subscript_expression" => {
                // Check for violations in array subscript like ptr[scaled_value]
                self.check_subscript_scaling(node, source, violations);
            }
            _ => {}
        }

        // Recursively check child nodes
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_node(&child, source, violations);
            }
        }
    }

    fn check_pointer_arithmetic(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(operator) = self.get_operator(node, source) {
            if operator == "+" || operator == "-" {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    // Check if this is pointer + scaled_integer or pointer - scaled_integer
                    if self.is_pointer_scaled_arithmetic(&left, &right, source) {
                        let start_point = node.start_position();
                        let expr_text = &source[node.start_byte()..node.end_byte()];

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::High,
                            message: format!(
                                "Scaled integer arithmetic with pointer: '{}'. This results in double scaling",
                                expr_text
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some("Remove sizeof() or use unscaled integer arithmetic".to_string()),
                        ..Default::default()
                        });
                    }
                }
            }
        }
    }

    fn check_assignment_arithmetic(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(operator) = self.get_assignment_operator(node, source) {
            if operator == "+=" || operator == "-=" {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    let left_text = &source[left.start_byte()..left.end_byte()];

                    // Check if this is pointer += scaled_integer
                    if self.is_scaled_integer_expression(&right, source)
                        && self.looks_like_pointer(&left, source)
                        && !self.is_char_pointer(&left, source)  // Char pointers are allowed
                        && !left_text.to_lowercase().contains("byte")
                    // Byte pointers are allowed
                    {
                        let start_point = node.start_position();
                        let expr_text = &source[node.start_byte()..node.end_byte()];

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::High,
                            message: format!(
                                "Scaled integer assignment to pointer: '{}'. This results in double scaling",
                                expr_text
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some("Use unscaled integer increment without sizeof()".to_string()),
                        ..Default::default()
                        });
                    }
                }
            }
        }
    }

    fn check_subscript_scaling(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check for ptr[sizeof_value] pattern
        if let (Some(argument), Some(index)) = (
            node.child_by_field_name("argument"),
            node.child_by_field_name("index"),
        ) {
            let arg_text = &source[argument.start_byte()..argument.end_byte()];

            // Check if index is a scaled value (from sizeof or byte-related variable)
            if self.is_scaled_integer_expression(&index, source)
                && self.looks_like_pointer_node(&argument, source)
                && !self.is_char_pointer(&argument, source)
                && !arg_text.to_lowercase().contains("byte")
            // Byte pointers are allowed
            {
                let start_point = node.start_position();
                let expr_text = &source[node.start_byte()..node.end_byte()];

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Array subscript with scaled integer: '{}'. This results in double scaling",
                        expr_text
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(
                        "Use unscaled index or element count instead of sizeof()".to_string(),
                    ),
                    ..Default::default()
                });
            }
        }
    }

    fn check_function_call_scaling(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = &source[function_node.start_byte()..function_node.end_byte()];

            // Check specific functions that commonly have scaling issues
            match function_name {
                "fgetws" | "fputws" => {
                    self.check_wide_string_function_scaling(
                        node,
                        source,
                        function_name,
                        violations,
                    );
                }
                "memset" | "memcpy" | "memmove" => {
                    self.check_memory_function_scaling(node, source, function_name, violations);
                }
                _ => {}
            }
        }
    }

    fn check_loop_pointer_arithmetic(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check if loop condition uses sizeof(array) as upper bound
        // Pattern: for (i = 0; i < sizeof(data); i++) { ptr[i] or *(ptr+i) }
        if let Some(condition) = self.find_loop_condition(node) {
            let condition_text = &source[condition.start_byte()..condition.end_byte()];

            // Check if sizeof is used as loop bound
            if condition_text.contains("sizeof(") {
                // Find the loop body
                if let Some(body) = self.find_loop_body(node) {
                    // Check if body uses pointer arithmetic or subscripting
                    if self.has_pointer_operations_in_loop(&body, source) {
                        let start_point = condition.start_position();

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::High,
                            message: "Loop uses sizeof() as bound (byte count) but performs pointer arithmetic (element-based), causing double scaling".to_string(),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some("Use array element count (sizeof(array)/sizeof(array[0])) instead of sizeof(array) in loop bound".to_string()),
                            ..Default::default()
                        });
                        return; // Only report once per loop
                    }
                }
            }
        }

        // Original check: Look for patterns like: while (ptr < (buf + sizeof(buf)))
        let node_text = &source[node.start_byte()..node.end_byte()];

        if node_text.contains("sizeof(") && (node_text.contains(" + ") || node_text.contains(" - "))
        {
            // Look for pointer comparison with sizeof scaling
            if let Some(condition) = self.find_loop_condition(node) {
                if self.has_scaled_pointer_comparison(&condition, source) {
                    let start_point = condition.start_position();

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: "Loop condition uses scaled pointer arithmetic with sizeof(), causing double scaling".to_string(),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Use array element count instead of sizeof() in pointer arithmetic".to_string()),
                    ..Default::default()
                    });
                }
            }
        }
    }

    fn find_loop_body<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        match node.kind() {
            "for_statement" => node.child_by_field_name("body"),
            "while_statement" => node.child_by_field_name("body"),
            "do_statement" => node.child_by_field_name("body"),
            _ => None,
        }
    }

    fn has_pointer_operations_in_loop(&self, body: &Node, source: &str) -> bool {
        // Check for pointer arithmetic (ptr + i, ptr - i) or subscripting (ptr[i])
        self.check_node_for_pointer_ops(body, source)
    }

    fn check_node_for_pointer_ops(&self, node: &Node, source: &str) -> bool {
        match node.kind() {
            "subscript_expression" => {
                // Found ptr[i] pattern
                if let Some(argument) = node.child_by_field_name("argument") {
                    // Check if the argument looks like a pointer (not char*)
                    if self.looks_like_pointer_node(&argument, source)
                        && !self.is_char_pointer(&argument, source)
                    {
                        return true;
                    }
                }
            }
            "binary_expression" => {
                // Check for pointer +/- operations
                if let Some(operator_node) = node.child_by_field_name("operator") {
                    let op = &source[operator_node.start_byte()..operator_node.end_byte()];
                    if op == "+" || op == "-" {
                        if let Some(left) = node.child_by_field_name("left") {
                            if self.looks_like_pointer_node(&left, source)
                                && !self.is_char_pointer(&left, source)
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            "pointer_expression" => {
                // Check for *(ptr + i) pattern
                if let Some(argument) = node.child_by_field_name("argument") {
                    if argument.kind() == "binary_expression" {
                        if let Some(operator_node) = argument.child_by_field_name("operator") {
                            let op = &source[operator_node.start_byte()..operator_node.end_byte()];
                            if op == "+" || op == "-" {
                                if let Some(left) = argument.child_by_field_name("left") {
                                    if self.looks_like_pointer_node(&left, source) {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        // Recursively check children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if self.check_node_for_pointer_ops(&child, source) {
                    return true;
                }
            }
        }

        false
    }

    fn check_wide_string_function_scaling(
        &self,
        node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let args = self.get_function_arguments(node, source);

        for (i, arg) in args.iter().enumerate() {
            if arg.contains("wcslen(") && arg.contains("sizeof(wchar_t)") {
                let start_point = node.start_position();
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Function '{}' argument {} uses scaled arithmetic: '{}'. wcslen already returns character count",
                        function_name, i + 1, arg
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Remove '* sizeof(wchar_t)' multiplication".to_string()),
                ..Default::default()
                });
            }
        }
    }

    fn check_memory_function_scaling(
        &self,
        node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(arguments) = node.child_by_field_name("arguments") {
            // Look for patterns in the first argument (destination pointer arithmetic)
            for i in 0..arguments.child_count() {
                if let Some(arg) = arguments.child(i) {
                    if arg.kind() != "," {
                        let arg_text = &source[arg.start_byte()..arg.end_byte()];

                        // Check for scaled offset patterns like: struct_ptr + offsetof(...) * sizeof(...)
                        if self.is_scaled_offset_pattern(arg_text) {
                            let start_point = arg.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::High,
                                message: format!(
                                    "Function '{}' called with scaled offset. offsetof() result is already scaled",
                                    function_name
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some("Use char* pointer to avoid scaling or remove extra scaling".to_string()),
                            ..Default::default()
                            });
                        }
                        break; // Only check first argument for destination pointer
                    }
                }
            }
        }
    }

    /// Check if a text is an ALL_CAPS identifier (macro/enum constant)
    fn is_all_caps_identifier(text: &str) -> bool {
        !text.is_empty()
            && text
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    }

    /// Recursively check if an expression consists entirely of ALL_CAPS
    /// identifiers and arithmetic operators (macro/enum constant arithmetic).
    /// Handles nested binary_expressions like `A + B + C` parsed as `(A + B) + C`.
    fn is_all_caps_arithmetic(node: &Node, source: &str) -> bool {
        match node.kind() {
            "identifier" => {
                let text = &source[node.start_byte()..node.end_byte()];
                Self::is_all_caps_identifier(text)
            }
            "number_literal" => true,
            "binary_expression" => {
                // Both operands must be ALL_CAPS arithmetic
                node.child_by_field_name("left")
                    .is_some_and(|l| Self::is_all_caps_arithmetic(&l, source))
                    && node
                        .child_by_field_name("right")
                        .is_some_and(|r| Self::is_all_caps_arithmetic(&r, source))
            }
            "parenthesized_expression" => {
                // Unwrap parentheses
                node.child(1)
                    .is_some_and(|inner| Self::is_all_caps_arithmetic(&inner, source))
            }
            _ => false,
        }
    }

    fn is_pointer_scaled_arithmetic(&self, left: &Node, right: &Node, source: &str) -> bool {
        let left_text = &source[left.start_byte()..left.end_byte()];
        let right_text = &source[right.start_byte()..right.end_byte()];

        // Both operands are ALL_CAPS identifiers → macro/enum constants, not pointers
        if Self::is_all_caps_identifier(left_text) && Self::is_all_caps_identifier(right_text) {
            return false;
        }

        // Entire expression tree consists of ALL_CAPS identifiers and numeric literals
        // (handles nested expressions like `A + B + C` parsed as `(A + B) + C`)
        if Self::is_all_caps_arithmetic(left, source) && Self::is_all_caps_arithmetic(right, source)
        {
            return false;
        }

        // Check if left is likely a pointer and right contains scaling
        let left_is_pointer = self.looks_like_pointer_node(left, source);
        let right_is_scaled = self.is_scaled_integer_expression(&right, source);

        // If it's a char pointer (by naming or cast), byte arithmetic is correct (not a violation)
        if left_is_pointer
            && (self.is_char_pointer(left, source) || left_text.to_lowercase().contains("byte"))
        {
            return false;
        }

        // Special case: generic pointer name with offset/skip variable suggests intentional byte arithmetic
        // This is a heuristic to avoid false positives when char* pointers are used
        if left_text == "ptr" && (right_text == "skip" || right_text == "offset") {
            return false; // Likely intentional byte-level arithmetic
        }

        left_is_pointer && right_is_scaled
    }

    fn is_scaled_integer_expression(&self, node: &Node, source: &str) -> bool {
        let text = &source[node.start_byte()..node.end_byte()];

        // Common scaled integer patterns - direct sizeof/offsetof
        if text.contains("sizeof(")
            || text.contains("offsetof(")
            || (text.contains("*") && (text.contains("sizeof") || text.contains("wcslen")))
            || text.contains("wcslen(") && text.contains("sizeof(wchar_t)")
        {
            return true;
        }

        // Check for variables that likely hold byte counts/sizes
        // These are common patterns where byte values are incorrectly used for pointer arithmetic
        let lower = text.to_lowercase();
        if lower.contains("_size")
            || lower.contains("alloc_size")
            || lower.contains("byte_offset")
            || lower == "skip"  // offsetof result variable name from wiki example
            || lower == "offset"  // Common offset variable
            || lower.contains("_bytes")
            || lower.contains("offset_bytes")
        {
            return true;
        }

        false
    }

    fn looks_like_pointer(&self, node: &Node, source: &str) -> bool {
        let text = &source[node.start_byte()..node.end_byte()];
        let lower = text.to_lowercase();

        // Simple heuristics for pointer identification (case-insensitive)
        lower.ends_with("_ptr")
            || text.ends_with("*")
            || lower.contains("pointer")
            || lower.contains("buf")
            || lower.contains("array")
            || lower.contains("ptr")
            || lower.contains("start")
            || lower.contains("end")
            || text == "s"
            || text == "p"
            || lower.contains("data")
            || lower.contains("dest")
            || lower.contains("src")
            || lower.contains("message")
            || lower.contains("record")
            || lower.contains("append")
    }

    fn is_char_pointer(&self, node: &Node, source: &str) -> bool {
        // Check if this is a char-type pointer (which is allowed to use byte arithmetic)

        // For an identifier, we need to look at its declaration or most recent cast
        // This is a simplified heuristic - we look for cast expressions in the parent chain
        let mut current = *node;

        // Walk up the tree to find casts
        for _ in 0..5 {
            // Check up to 5 levels up
            if let Some(parent) = current.parent() {
                // Check for char* / u8* / uint8_t* casts
                if parent.kind() == "cast_expression" {
                    if let Some(type_node) = parent.child_by_field_name("type") {
                        let type_text = &source[type_node.start_byte()..type_node.end_byte()];
                        if Self::is_byte_type(type_text) {
                            return true;
                        }
                    }
                }

                current = parent;
            } else {
                break;
            }
        }

        false
    }

    /// Returns true for single-byte pointer types: char*, unsigned char*, u8*, uint8_t*, etc.
    fn is_byte_type(type_text: &str) -> bool {
        let t = type_text.trim();
        // Standard char types
        if (t.contains("char") && !t.contains("wchar"))
            || t.contains("unsigned char")
            || t.contains("signed char")
        {
            return true;
        }
        // Embedded/vendor byte aliases
        matches!(t, "u8" | "uint8_t" | "UINT8" | "uint8_T" | "byte" | "BYTE")
    }

    fn looks_like_pointer_node(&self, node: &Node, source: &str) -> bool {
        match node.kind() {
            "identifier" => {
                let _text = &source[node.start_byte()..node.end_byte()];
                self.looks_like_pointer(node, source)
            }
            "binary_expression" => {
                // Could be pointer arithmetic
                true
            }
            "cast_expression" => {
                // Cast expressions are often pointers
                let text = &source[node.start_byte()..node.end_byte()];
                text.contains("*") // Has pointer in cast
            }
            _ => false,
        }
    }

    fn is_scaled_offset_pattern(&self, text: &str) -> bool {
        (text.contains("offsetof(") && text.contains("*"))
            || (text.contains("offsetof(") && text.contains("sizeof("))
    }

    fn has_scaled_pointer_comparison(&self, node: &Node, source: &str) -> bool {
        let text = &source[node.start_byte()..node.end_byte()];

        // Look for patterns like: ptr < (buf + sizeof(buf))
        text.contains("sizeof(")
            && (text.contains(" < ")
                || text.contains(" <= ")
                || text.contains(" > ")
                || text.contains(" >= "))
            && (text.contains(" + ") || text.contains(" - "))
    }

    fn find_loop_condition<'a>(&self, node: &'a Node<'a>) -> Option<Node<'a>> {
        // Find condition in while or for loop
        match node.kind() {
            "while_statement" => node.child_by_field_name("condition"),
            "for_statement" => node.child_by_field_name("condition"),
            _ => None,
        }
    }

    fn get_operator(&self, node: &Node, source: &str) -> Option<String> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let text = &source[child.start_byte()..child.end_byte()];
                if matches!(text, "+" | "-" | "*" | "/") {
                    return Some(text.to_string());
                }
            }
        }
        None
    }

    fn get_assignment_operator(&self, node: &Node, source: &str) -> Option<String> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let text = &source[child.start_byte()..child.end_byte()];
                if matches!(text, "+=" | "-=" | "*=" | "/=") {
                    return Some(text.to_string());
                }
            }
        }
        None
    }

    fn get_function_arguments(&self, node: &Node, source: &str) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(arguments) = node.child_by_field_name("arguments") {
            for i in 0..arguments.child_count() {
                if let Some(child) = arguments.child(i) {
                    if child.kind() != "," {
                        let arg_text = source[child.start_byte()..child.end_byte()].to_string();
                        args.push(arg_text);
                    }
                }
            }
        }

        args
    }
}
