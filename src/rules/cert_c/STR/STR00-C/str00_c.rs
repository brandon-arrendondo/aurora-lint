//! STR00-C: Represent characters using an appropriate type
//!
//! Character types must be chosen appropriately:
//! - Use `int` for character I/O functions that return EOF
//! - Cast to `unsigned char` before passing to character classification functions
//! - Use `unsigned char` for byte operations where all bits matter
//! - Don't use plain `char` for numeric values where signedness matters
//!
//! ## Key Violations:
//! 1. `char c = getchar()` - should use `int`
//! 2. `char c = fgetc()/getc()` - should use `int`
//! 3. Comparing plain `char` with `EOF`
//! 4. `char c = toupper(x)/tolower(x)` - these return `int`
//! 5. Passing plain `char` to `isspace()` etc without `(unsigned char)` cast
//! 6. Using plain `char` for byte values with values > 127 (signedness issues)
//! 7. Using plain `char` for bit operations (should use `unsigned char`)

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Str00C;

impl CertRule for Str00C {
    fn rule_id(&self) -> &'static str {
        "STR00-C"
    }

    fn description(&self) -> &'static str {
        "Represent characters using an appropriate type"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "STR00-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Track variable types to detect inappropriate usage
        let mut char_vars = HashMap::new();
        let mut wchar_vars = HashMap::new();
        let mut int_vars = HashMap::new();

        self.collect_char_variables(node, source, &mut char_vars);
        self.collect_wchar_variables(node, source, &mut wchar_vars);
        self.collect_int_variables(node, source, &mut int_vars);

        self.check_node(
            node,
            source,
            &char_vars,
            &wchar_vars,
            &int_vars,
            &mut violations,
        );
        violations
    }
}

impl Str00C {
    /// Collect all variables declared as plain 'char' type
    fn collect_char_variables(
        &self,
        node: &Node,
        source: &str,
        char_vars: &mut HashMap<String, usize>,
    ) {
        for node in query::find_descendants_of_kind(*node, "declaration") {
            if let Some(type_node) = node.child_by_field_name("type") {
                let type_text = get_node_text(&type_node, source);

                // Check if it's plain char (not unsigned char, not signed char)
                if self.is_plain_char_type(&type_text) {
                    // Get the declarator(s)
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            if child.kind() == "init_declarator" {
                                if let Some(declarator) = child.child_by_field_name("declarator") {
                                    if let Some(var_name) =
                                        self.get_declarator_name(&declarator, source)
                                    {
                                        char_vars.insert(var_name, node.start_position().row);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Collect all variables declared as wchar_t type
    fn collect_wchar_variables(
        &self,
        node: &Node,
        source: &str,
        wchar_vars: &mut HashMap<String, usize>,
    ) {
        for node in query::find_descendants_of_kind(*node, "declaration") {
            if let Some(type_node) = node.child_by_field_name("type") {
                let type_text = get_node_text(&type_node, source);

                if type_text.contains("wchar_t") {
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            // Handle both init_declarator (with initialization) and plain declarator (without)
                            if child.kind() == "init_declarator" {
                                if let Some(declarator) = child.child_by_field_name("declarator") {
                                    if let Some(var_name) =
                                        self.get_declarator_name(&declarator, source)
                                    {
                                        wchar_vars.insert(var_name, node.start_position().row);
                                    }
                                }
                            } else if child.kind() == "array_declarator"
                                || child.kind() == "pointer_declarator"
                                || child.kind() == "identifier"
                            {
                                // Plain declarator without initialization
                                if let Some(var_name) = self.get_declarator_name(&child, source) {
                                    wchar_vars.insert(var_name, node.start_position().row);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Collect all variables declared as int type
    fn collect_int_variables(
        &self,
        node: &Node,
        source: &str,
        int_vars: &mut HashMap<String, usize>,
    ) {
        for node in query::find_descendants_of_kind(*node, "declaration") {
            if let Some(type_node) = node.child_by_field_name("type") {
                let type_text = get_node_text(&type_node, source);

                // Check for plain int arrays (not single int variables - those are OK for arithmetic)
                let trimmed = type_text.trim();
                if trimmed == "int" {
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            if child.kind() == "init_declarator" {
                                if let Some(declarator) = child.child_by_field_name("declarator") {
                                    // Only track int arrays, not single int variables
                                    if declarator.kind() == "array_declarator" {
                                        if let Some(var_name) =
                                            self.get_declarator_name(&declarator, source)
                                        {
                                            int_vars.insert(var_name, node.start_position().row);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn is_plain_char_type(&self, type_text: &str) -> bool {
        let trimmed = type_text.trim();
        // Plain char, not unsigned char or signed char
        trimmed == "char"
            || (trimmed.contains("char")
                && !trimmed.contains("unsigned")
                && !trimmed.contains("signed")
                && !trimmed.contains("wchar_t"))
    }

    fn get_declarator_name(&self, declarator: &Node, source: &str) -> Option<String> {
        match declarator.kind() {
            "identifier" => Some(get_node_text(declarator, source).to_string()),
            "array_declarator" | "pointer_declarator" => {
                if let Some(inner) = declarator.child_by_field_name("declarator") {
                    self.get_declarator_name(&inner, source)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        char_vars: &HashMap<String, usize>,
        wchar_vars: &HashMap<String, usize>,
        int_vars: &HashMap<String, usize>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for node in query::find_descendants(*node, |_| true) {
            let node = &node;
            // Check for assignments from EOF-related functions to char variables
            if node.kind() == "assignment_expression" || node.kind() == "init_declarator" {
                self.check_eof_function_assignment(node, source, char_vars, violations);
            }

            // Check for calls to character classification functions
            if node.kind() == "call_expression" {
                if let Some(function) = node.child_by_field_name("function") {
                    let func_name = get_node_text(&function, source);

                    if self.is_char_classification_function(func_name) {
                        self.check_char_classification_call(node, source, char_vars, violations);
                    }
                }
            }

            // Check for EOF comparisons with char variables
            if node.kind() == "binary_expression" {
                self.check_eof_comparison(node, source, char_vars, violations);
            }

            // Check for char used with bit operations
            if node.kind() == "binary_expression" {
                self.check_bit_operations(node, source, char_vars, violations);
            }

            // Check for char literals > 127 assigned to plain char
            if node.kind() == "assignment_expression" || node.kind() == "init_declarator" {
                self.check_high_value_assignment(node, source, char_vars, violations);
            }

            // Check for char used as array index
            if node.kind() == "subscript_expression" {
                self.check_char_array_index(node, source, char_vars, violations);
            }

            // Check for signed/unsigned char with character constants
            if node.kind() == "declaration" {
                self.check_signed_unsigned_char_constants(node, source, violations);
            }

            // Check for signed/unsigned char function parameters
            if node.kind() == "parameter_declaration" {
                self.check_function_parameter_types(node, source, violations);
            }

            // Check for signed/unsigned char struct members
            if node.kind() == "field_declaration" {
                self.check_struct_field_types(node, source, violations);
            }

            // Check for narrow char constants assigned to wchar_t
            if node.kind() == "assignment_expression" || node.kind() == "init_declarator" {
                self.check_wchar_narrow_char(node, source, wchar_vars, violations);
            }

            // Check for character constants assigned to int
            if node.kind() == "assignment_expression" || node.kind() == "init_declarator" {
                self.check_int_char_constants(node, source, int_vars, violations);
            }
        }
    }

    /// Check for char = getchar()/fgetc()/getc()/toupper()/tolower()
    fn check_eof_function_assignment(
        &self,
        node: &Node,
        source: &str,
        char_vars: &HashMap<String, usize>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let (left, right) = if node.kind() == "assignment_expression" {
            (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            )
        } else if node.kind() == "init_declarator" {
            (
                node.child_by_field_name("declarator"),
                node.child_by_field_name("value"),
            )
        } else {
            return;
        };

        if let (Some(left_node), Some(right_node)) = (left, right) {
            // Check if left side is a char variable
            let left_text = get_node_text(&left_node, source);
            let var_name = self.extract_var_name(&left_text);

            if char_vars.contains_key(var_name) {
                // Skip if there's an explicit cast to char (which is intentional)
                if self.has_explicit_char_cast(right_node, source) {
                    return;
                }

                // Check if right side is a function that returns int for EOF handling
                if let Some(call_expr) = self.find_call_expression(right_node) {
                    if let Some(func) = call_expr.child_by_field_name("function") {
                        let func_name = get_node_text(&func, source);

                        if self.is_eof_related_function(func_name) {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::Medium,
                                message: format!(
                                    "Plain 'char' variable '{}' assigned from '{}()' which returns 'int' for EOF handling",
                                    var_name, func_name
                                ),
                                file_path: String::new(),
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                                suggestion: Some(format!(
                                    "Declare '{}' as 'int' instead of 'char' to properly handle EOF: int {} = {}()",
                                    var_name, var_name, func_name
                                )),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    fn find_call_expression<'a>(&self, node: Node<'a>) -> Option<Node<'a>> {
        query::find_first_descendant(node, |n| n.kind() == "call_expression")
    }

    /// Check if the right side has an explicit cast to char
    fn has_explicit_char_cast(&self, node: Node, source: &str) -> bool {
        if node.kind() == "cast_expression" {
            if let Some(type_node) = node.child_by_field_name("type") {
                let type_text = get_node_text(&type_node, source);
                // Check for (char) cast
                if type_text.contains("char")
                    && !type_text.contains("unsigned")
                    && !type_text.contains("signed")
                    && !type_text.contains("*")
                {
                    return true;
                }
            }
        }
        false
    }

    fn extract_var_name<'a>(&self, text: &'a str) -> &'a str {
        // Handle array subscripts, field access, etc.
        text.split('[')
            .next()
            .and_then(|s| s.split('.').next())
            .and_then(|s| s.split("->").next())
            .unwrap_or(text)
            .trim()
    }

    fn is_eof_related_function(&self, name: &str) -> bool {
        const EOF_FUNCTIONS: &[&str] =
            &["getchar", "fgetc", "getc", "ungetc", "toupper", "tolower"];
        EOF_FUNCTIONS.contains(&name)
    }

    /// Character classification functions that require unsigned char or EOF
    fn is_char_classification_function(&self, name: &str) -> bool {
        const CHAR_CLASS_FUNCTIONS: &[&str] = &[
            "isalnum", "isalpha", "isblank", "iscntrl", "isdigit", "isgraph", "islower", "isprint",
            "ispunct", "isspace", "isupper", "isxdigit",
        ];
        CHAR_CLASS_FUNCTIONS.contains(&name)
    }

    fn check_char_classification_call(
        &self,
        node: &Node,
        source: &str,
        char_vars: &HashMap<String, usize>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let (Some(function), Some(args)) = (
            node.child_by_field_name("function"),
            node.child_by_field_name("arguments"),
        ) {
            let func_name = get_node_text(&function, source);

            // Get first argument
            for i in 0..args.child_count() {
                if let Some(arg) = args.child(i) {
                    if arg.kind() != "," && arg.kind() != "(" && arg.kind() != ")" {
                        // Check if argument is plain char without unsigned cast
                        if self.is_plain_char_arg(&arg, source, char_vars) {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::Medium,
                                message: format!(
                                    "Plain 'char' passed to '{}()' without cast to 'unsigned char'",
                                    func_name
                                ),
                                file_path: String::new(),
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                                suggestion: Some(format!(
                                    "Cast to '(unsigned char)' before passing to '{}()': {}((unsigned char){})",
                                    func_name, func_name, get_node_text(&arg, source)
                                )),
                                ..Default::default()
                            });
                        }
                        break; // Only check first arg
                    }
                }
            }
        }
    }

    fn is_plain_char_arg(
        &self,
        node: &Node,
        source: &str,
        char_vars: &HashMap<String, usize>,
    ) -> bool {
        match node.kind() {
            "identifier" => {
                let var_name = get_node_text(node, source);
                char_vars.contains_key(var_name)
            }
            "subscript_expression" | "field_expression" | "pointer_expression" => {
                // Could be accessing char array/struct member
                true
            }
            "cast_expression" => {
                // If explicitly cast to unsigned char or int, it's OK
                if let Some(type_node) = node.child_by_field_name("type") {
                    let type_text = get_node_text(&type_node, source);
                    if type_text.contains("unsigned") || type_text.contains("int") {
                        return false;
                    }
                }
                // Otherwise check the value being cast
                if let Some(value) = node.child_by_field_name("value") {
                    return self.is_plain_char_arg(&value, source, char_vars);
                }
                false
            }
            _ => false,
        }
    }

    fn check_eof_comparison(
        &self,
        node: &Node,
        source: &str,
        char_vars: &HashMap<String, usize>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let left_text = get_node_text(&left, source);
            let right_text = get_node_text(&right, source);

            // Check if comparing char variable with EOF
            let var_name = self.extract_var_name(&left_text);
            if char_vars.contains_key(var_name) && right_text.contains("EOF") {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "Plain 'char' variable '{}' compared with EOF (undefined behavior)",
                        var_name
                    ),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some(format!(
                        "Declare '{}' as 'int' to properly handle EOF comparisons",
                        var_name
                    )),
                    ..Default::default()
                });
            }

            // Check reverse (EOF on left)
            let var_name_right = self.extract_var_name(&right_text);
            if char_vars.contains_key(var_name_right) && left_text.contains("EOF") {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "Plain 'char' variable '{}' compared with EOF (undefined behavior)",
                        var_name_right
                    ),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some(format!(
                        "Declare '{}' as 'int' to properly handle EOF comparisons",
                        var_name_right
                    )),
                    ..Default::default()
                });
            }
        }
    }

    fn check_bit_operations(
        &self,
        node: &Node,
        source: &str,
        char_vars: &HashMap<String, usize>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(operator) = node.child_by_field_name("operator") {
            let op = get_node_text(&operator, source);

            // Check for bitwise operations
            if op == "&" || op == "|" || op == "^" || op == "<<" || op == ">>" {
                if let Some(left) = node.child_by_field_name("left") {
                    let left_text = get_node_text(&left, source);
                    let var_name = self.extract_var_name(&left_text);

                    if char_vars.contains_key(var_name) {
                        // Check if the right operand is a hex value suggesting bit manipulation
                        if let Some(right) = node.child_by_field_name("right") {
                            let right_text = get_node_text(&right, source);
                            if right_text.starts_with("0x") || right_text.starts_with("0X") {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::Medium,
                                    message: format!(
                                        "Plain 'char' variable '{}' used in bit operation (signedness issues)",
                                        var_name
                                    ),
                                    file_path: String::new(),
                                    line: node.start_position().row + 1,
                                    column: node.start_position().column + 1,
                                    suggestion: Some(format!(
                                        "Declare '{}' as 'unsigned char' for bit operations",
                                        var_name
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

    fn check_high_value_assignment(
        &self,
        node: &Node,
        source: &str,
        char_vars: &HashMap<String, usize>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let (left, right) = if node.kind() == "assignment_expression" {
            (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            )
        } else if node.kind() == "init_declarator" {
            (
                node.child_by_field_name("declarator"),
                node.child_by_field_name("value"),
            )
        } else {
            return;
        };

        if let (Some(left_node), Some(right_node)) = (left, right) {
            let left_text = get_node_text(&left_node, source);
            let var_name = self.extract_var_name(&left_text);

            if char_vars.contains_key(var_name) {
                let right_text = get_node_text(&right_node, source);

                // Check for numeric literals > 127
                if let Ok(value) = right_text.trim().parse::<i32>() {
                    if !(0..=127).contains(&value) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Medium,
                            message: format!(
                                "Plain 'char' variable '{}' assigned value {} (signedness-dependent)",
                                var_name, value
                            ),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some(format!(
                                "Declare '{}' as 'unsigned char' for byte values or use smaller values for plain char",
                                var_name
                            )),
                            ..Default::default()
                        });
                    }
                }

                // Check for hex literals that might be > 127
                if right_text.starts_with("0x") || right_text.starts_with("0X") {
                    if let Ok(value) = i32::from_str_radix(&right_text[2..], 16) {
                        if value > 127 {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::Medium,
                                message: format!(
                                    "Plain 'char' variable '{}' assigned hex value {} (signedness-dependent)",
                                    var_name, right_text
                                ),
                                file_path: String::new(),
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                                suggestion: Some(format!(
                                    "Declare '{}' as 'unsigned char' for byte values",
                                    var_name
                                )),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    fn check_char_array_index(
        &self,
        node: &Node,
        source: &str,
        char_vars: &HashMap<String, usize>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(index) = node.child_by_field_name("index") {
            let index_text = get_node_text(&index, source);
            let var_name = self.extract_var_name(&index_text);

            if char_vars.contains_key(var_name) {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "Plain 'char' variable '{}' used as array index (may be negative)",
                        var_name
                    ),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some(format!(
                        "Declare '{}' as 'unsigned char' or 'int' for array indexing",
                        var_name
                    )),
                    ..Default::default()
                });
            }
        }
    }

    /// Check for signed/unsigned char with character constants
    fn check_signed_unsigned_char_constants(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(type_node) = node.child_by_field_name("type") {
            let type_text = get_node_text(&type_node, source);

            // Check if it's signed or unsigned char (not plain char)
            if type_text.contains("signed")
                && type_text.contains("char")
                && !type_text.contains("*")
            {
                // Look for initializers with character constants
                for i in 0..node.child_count() {
                    if let Some(declarator) = node.child(i) {
                        if declarator.kind() == "init_declarator" {
                            if let Some(value) = declarator.child_by_field_name("value") {
                                let value_text = get_node_text(&value, source);

                                // Check for character constant (e.g., 'A', '\n', L'W') or string literal
                                let is_string_literal = value_text.trim().starts_with("\"");
                                let is_char_constant = value_text.trim().starts_with("'")
                                    || value_text.trim().starts_with("L'");

                                // Flag signed char with character constants or string literals
                                // Flag unsigned char with character constants only (unsigned char is OK for byte strings)
                                let is_unsigned = type_text.contains("unsigned");
                                let should_flag = if is_unsigned {
                                    is_char_constant // Only flag character constants, not string literals for unsigned char
                                } else {
                                    is_char_constant || is_string_literal // Flag both for signed char
                                };

                                if should_flag {
                                    let char_type = if is_unsigned {
                                        "unsigned char"
                                    } else {
                                        "signed char"
                                    };

                                    let literal_type = if is_string_literal {
                                        "string literal"
                                    } else {
                                        "character constant"
                                    };

                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        severity: Severity::Medium,
                                        message: format!(
                                            "{} assigned to '{}' (should use plain 'char')",
                                            literal_type, char_type
                                        ),
                                        file_path: String::new(),
                                        line: declarator.start_position().row + 1,
                                        column: declarator.start_position().column + 1,
                                        suggestion: Some(format!(
                                            "Use plain 'char' instead of '{}' for {}",
                                            char_type, literal_type
                                        )),
                                        ..Default::default()
                                    });
                                }

                                // Check for array initializer with character constants
                                if value.kind() == "initializer_list" {
                                    for j in 0..value.child_count() {
                                        if let Some(element) = value.child(j) {
                                            let elem_text = get_node_text(&element, source);
                                            if elem_text.trim().starts_with("'")
                                                || elem_text.trim().starts_with("L'")
                                            {
                                                let char_type = if type_text.contains("unsigned") {
                                                    "unsigned char"
                                                } else {
                                                    "signed char"
                                                };

                                                violations.push(RuleViolation {
                                                    rule_id: self.rule_id().to_string(),
                                                    severity: Severity::Medium,
                                                    message: format!(
                                                        "Character constant in '{}' array initializer (should use plain 'char')",
                                                        char_type
                                                    ),
                                                    file_path: String::new(),
                                                    line: element.start_position().row + 1,
                                                    column: element.start_position().column + 1,
                                                    suggestion: Some(format!(
                                                        "Use plain 'char' instead of '{}' for character arrays",
                                                        char_type
                                                    )),
                                                    ..Default::default()
                                                });
                                                break; // One violation per array is enough
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check for signed/unsigned char* function parameters
    fn check_function_parameter_types(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(type_node) = node.child_by_field_name("type") {
            let type_text = get_node_text(&type_node, source);

            // Check if type is signed char (not unsigned - unsigned char* is OK for byte ops)
            let is_signed_char = type_text.contains("signed")
                && !type_text.contains("unsigned")
                && type_text.contains("char");

            if is_signed_char {
                // Check if declarator is a pointer
                let mut is_pointer = false;
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    if declarator.kind() == "pointer_declarator" {
                        is_pointer = true;
                    }
                }

                // Also check if the whole node text contains *
                let full_text = get_node_text(node, source);
                if full_text.contains("*") {
                    is_pointer = true;
                }

                if is_pointer {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Medium,
                        message: "Function parameter uses 'signed char*' (should use plain 'char*' for strings)".to_string(),
                        file_path: String::new(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        suggestion: Some(
                            "Use plain 'char*' instead of 'signed char*' for string parameters".to_string()
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Check for signed char struct fields (unsigned char is OK for byte data)
    fn check_struct_field_types(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(type_node) = node.child_by_field_name("type") {
            let type_text = get_node_text(&type_node, source);

            // Only flag signed char (not unsigned - unsigned char is OK for byte fields)
            let is_signed_char = type_text.contains("signed")
                && !type_text.contains("unsigned")
                && type_text.contains("char");

            if is_signed_char {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Medium,
                    message: "Struct field uses 'signed char' (should use plain 'char' for character data)".to_string(),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some(
                        "Use plain 'char' instead of 'signed char' for character struct fields".to_string()
                    ),
                    ..Default::default()
                });
            }
        }
    }

    /// Check for narrow char constants assigned to wchar_t variables
    fn check_wchar_narrow_char(
        &self,
        node: &Node,
        source: &str,
        wchar_vars: &HashMap<String, usize>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let (left, right) = if node.kind() == "assignment_expression" {
            (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            )
        } else if node.kind() == "init_declarator" {
            (
                node.child_by_field_name("declarator"),
                node.child_by_field_name("value"),
            )
        } else {
            return;
        };

        if let (Some(left_node), Some(right_node)) = (left, right) {
            let left_text = get_node_text(&left_node, source);
            let var_name = self.extract_var_name(&left_text);

            // Check if left side is a wchar_t variable
            if wchar_vars.contains_key(var_name) {
                let right_text = get_node_text(&right_node, source).trim().to_string();

                // Check if right side is a narrow char constant (not L'x')
                if right_text.starts_with("'") && !right_text.starts_with("L'") {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Medium,
                        message: format!(
                            "Narrow character constant {} assigned to wchar_t variable '{}' (use L'{}' instead)",
                            right_text,
                            var_name,
                            right_text.trim_matches('\'')
                        ),
                        file_path: String::new(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        suggestion: Some(format!(
                            "Use wide character constant L{} for wchar_t variable",
                            right_text
                        )),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Check for character constants assigned to int variables
    fn check_int_char_constants(
        &self,
        node: &Node,
        source: &str,
        int_vars: &HashMap<String, usize>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let (left, right) = if node.kind() == "assignment_expression" {
            (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            )
        } else if node.kind() == "init_declarator" {
            (
                node.child_by_field_name("declarator"),
                node.child_by_field_name("value"),
            )
        } else {
            return;
        };

        if let (Some(left_node), Some(right_node)) = (left, right) {
            let left_text = get_node_text(&left_node, source);
            let var_name = self.extract_var_name(&left_text);

            // Check if left side is an int variable
            if int_vars.contains_key(var_name) {
                let right_text = get_node_text(&right_node, source).trim().to_string();

                // Check if right side is a character constant
                if (right_text.starts_with("'") && !right_text.starts_with("L'"))
                    || (right_node.kind() == "initializer_list"
                        && self.contains_char_constants(&right_node, source))
                {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Medium,
                        message: format!(
                            "Character constant assigned to 'int' array '{}' (use 'char' for character/string storage)",
                            var_name
                        ),
                        file_path: String::new(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        suggestion: Some(format!(
                            "Declare '{}' as 'char' array instead of 'int' for character/string storage",
                            var_name
                        )),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Check if initializer list contains character constants
    fn contains_char_constants(&self, node: &Node, source: &str) -> bool {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let text = get_node_text(&child, source).trim();
                if text.starts_with("'") && !text.starts_with("L'") {
                    return true;
                }
            }
        }
        false
    }
}
