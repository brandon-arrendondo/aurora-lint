use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Str34C;

impl CertRule for Str34C {
    fn rule_id(&self) -> &'static str {
        "STR34-C"
    }

    fn description(&self) -> &'static str {
        "Cast characters to unsigned char before converting to larger integer sizes"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "STR34-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Process each function independently to scope char_vars per function
        self.check_translation_unit(node, source, &mut violations);

        violations
    }
}

impl Str34C {
    /// Process each function definition with its own scoped char_vars
    fn check_translation_unit(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() == "function_definition" {
            // Collect char variables scoped to this function
            let mut char_vars: HashMap<String, (usize, bool, usize)> = HashMap::new();
            self.collect_char_variables(node, source, &mut char_vars);
            self.check_node(node, source, &char_vars, violations);
            return; // Don't recurse further into this function
        }

        // For non-function nodes, also check with file-scope char_vars
        // (handles global declarations)
        if node.kind() == "translation_unit" {
            let mut file_char_vars: HashMap<String, (usize, bool, usize)> = HashMap::new();
            // Collect only file-scope declarations (not inside functions)
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "declaration" {
                        self.collect_char_variables(&child, source, &mut file_char_vars);
                    }
                }
            }
            // Check file-scope code with file-scope vars
            if !file_char_vars.is_empty() {
                self.check_node(node, source, &file_char_vars, violations);
            }
        }

        // Recurse to find function_definitions
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_translation_unit(&child, source, violations);
            }
        }
    }

    /// Collect all char pointer variables (char *, signed char *, unsigned char *)
    fn collect_char_variables(
        &self,
        node: &Node,
        source: &str,
        char_vars: &mut HashMap<String, (usize, bool, usize)>,
    ) {
        for n in query::find_descendants(*node, |_| true) {
            if n.kind() == "declaration" {
                if let Some(type_node) = n.child_by_field_name("type") {
                    let type_text = get_node_text(&type_node, source);
                    let trimmed = type_text.trim();

                    // Check for any char type (signed, unsigned, or plain)
                    let is_signed_char = trimmed == "signed char";
                    let is_plain_char = trimmed == "char";
                    let _is_unsigned_char = trimmed == "unsigned char";

                    if is_signed_char || is_plain_char {
                        // Extract variable names from declarators
                        // Only track signed/plain char pointer variables — unsigned char
                        // doesn't need cast to unsigned char before widening
                        for i in 0..n.child_count() {
                            if let Some(child) = n.child(i) {
                                if child.kind() == "init_declarator" {
                                    if let Some(declarator) =
                                        child.child_by_field_name("declarator")
                                    {
                                        // Check if it's a pointer declarator
                                        if declarator.kind() == "pointer_declarator" {
                                            if let Some(var_name) =
                                                self.get_declarator_name(&declarator, source)
                                            {
                                                let depth = self.declarator_depth(&declarator);
                                                char_vars.insert(
                                                    var_name,
                                                    (n.start_position().row, is_signed_char, depth),
                                                );
                                            }
                                        }
                                    }
                                } else if child.kind() == "pointer_declarator" {
                                    // Plain declarator without initialization
                                    if let Some(var_name) = self.get_declarator_name(&child, source)
                                    {
                                        let depth = self.declarator_depth(&child);
                                        char_vars.insert(
                                            var_name,
                                            (n.start_position().row, is_signed_char, depth),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Track char pointer/array function parameters
            if n.kind() == "parameter_declaration" {
                // Use full parameter text to check for unsigned char (tree-sitter may
                // split "unsigned char" across type and qualifier nodes)
                let full_param_text = get_node_text(&n, source);
                let has_unsigned = full_param_text.contains("unsigned");

                if let Some(type_node) = n.child_by_field_name("type") {
                    let type_text = get_node_text(&type_node, source);
                    let trimmed = type_text.trim();
                    // Strip const/volatile qualifiers for matching
                    let base_type = trimmed
                        .replace("const ", "")
                        .replace("volatile ", "")
                        .trim()
                        .to_string();

                    let is_signed_char = base_type == "signed char";
                    let is_plain_char = base_type == "char" && !has_unsigned;

                    if is_signed_char || is_plain_char {
                        if let Some(declarator) = n.child_by_field_name("declarator") {
                            // pointer_declarator (char *str) or array_declarator (char buf[])
                            if declarator.kind() == "pointer_declarator"
                                || declarator.kind() == "array_declarator"
                            {
                                if let Some(var_name) =
                                    self.get_declarator_name(&declarator, source)
                                {
                                    let depth = self.declarator_depth(&declarator);
                                    char_vars.insert(
                                        var_name,
                                        (n.start_position().row, is_signed_char, depth),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// True when `name` is a tracked char-pointer/array variable at exactly
    /// one level of indirection -- the only depth at which a single
    /// `*name`/`name[i]` dereference actually yields a scalar `char`. At
    /// depth > 1 (`char **`, `char ***`, ...) the same syntax yields another
    /// pointer, not a char (task 430).
    fn is_single_indirection_char(
        &self,
        char_vars: &HashMap<String, (usize, bool, usize)>,
        name: &str,
    ) -> bool {
        char_vars.get(name).is_some_and(|&(_, _, depth)| depth == 1)
    }

    /// Count levels of pointer/array indirection in a declarator chain (e.g.
    /// `***if_names` is depth 3, `*str` is depth 1, `buf[]` is depth 1).
    /// A single `*`/`[]` on the tracked variable only reaches a scalar
    /// `char` when depth is exactly 1 -- at depth > 1 it yields another
    /// pointer, so treating it as a char-widening site misclassifies e.g.
    /// `char **`/`char ***` as plain `char` (task 430).
    fn declarator_depth(&self, node: &Node) -> usize {
        match node.kind() {
            "pointer_declarator" | "array_declarator" => {
                let inner_depth = node
                    .child_by_field_name("declarator")
                    .map(|inner| self.declarator_depth(&inner))
                    .unwrap_or(0);
                1 + inner_depth
            }
            _ => 0,
        }
    }

    /// Extract variable name from declarator
    fn get_declarator_name(&self, node: &Node, source: &str) -> Option<String> {
        match node.kind() {
            "identifier" => Some(get_node_text(node, source).to_string()),
            "array_declarator" | "pointer_declarator" => {
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    self.get_declarator_name(&declarator, source)
                } else {
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            if child.kind() == "identifier" {
                                return Some(get_node_text(&child, source).to_string());
                            }
                        }
                    }
                    None
                }
            }
            _ => None,
        }
    }

    /// Check node and its children for violations
    fn check_node(
        &self,
        node: &Node,
        source: &str,
        char_vars: &HashMap<String, (usize, bool, usize)>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants(*node, |_| true) {
            // Check for direct assignment to larger integer types
            if n.kind() == "init_declarator" {
                self.check_init_declarator(&n, source, char_vars, violations);
            }

            // Check for assignment expressions
            if n.kind() == "assignment_expression" {
                self.check_assignment_expression(&n, source, char_vars, violations);
            }

            // Check for subscript expressions (array indexing)
            if n.kind() == "subscript_expression" {
                self.check_subscript_expression(&n, source, char_vars, violations);
            }

            // Check for pointer dereferences assigned to larger types
            if n.kind() == "pointer_expression" {
                self.check_pointer_expression(&n, source, char_vars, violations);
            }

            // Check for cast expressions that cast char to larger types
            if n.kind() == "cast_expression" {
                self.check_cast_expression(&n, source, char_vars, violations);
            }
        }
    }

    /// Check init_declarator for problematic assignments
    fn check_init_declarator(
        &self,
        node: &Node,
        source: &str,
        char_vars: &HashMap<String, (usize, bool, usize)>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(_declarator) = node.child_by_field_name("declarator") {
            if let Some(value) = node.child_by_field_name("value") {
                // Check if the declarator is a larger integer type
                if let Some(parent) = node.parent() {
                    if parent.kind() == "declaration" {
                        if let Some(type_node) = parent.child_by_field_name("type") {
                            let type_text = get_node_text(&type_node, source);

                            if self.is_larger_integer_type(&type_text) {
                                // Check if value involves a char variable without proper cast
                                self.check_char_usage_in_expression(
                                    &value, source, char_vars, violations,
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check assignment expressions
    fn check_assignment_expression(
        &self,
        node: &Node,
        source: &str,
        char_vars: &HashMap<String, (usize, bool, usize)>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(_left) = node.child_by_field_name("left") {
            if let Some(right) = node.child_by_field_name("right") {
                // Only check if the right side is a pointer dereference WITHOUT a cast
                // (If it has a cast, it will be checked by check_cast_expression)
                if right.kind() == "pointer_expression" || right.kind() == "update_expression" {
                    // Check if it involves a char pointer dereference
                    self.check_pointer_dereference_in_expression(
                        &right, source, char_vars, violations,
                    );
                }
            }
        }
    }

    /// Check for pointer dereferences in expressions
    fn check_pointer_dereference_in_expression(
        &self,
        node: &Node,
        source: &str,
        char_vars: &HashMap<String, (usize, bool, usize)>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check if this is a pointer expression (*ptr)
        if node.kind() == "pointer_expression" {
            if let Some(argument) = node.child_by_field_name("argument") {
                if let Some(base_name) = self.extract_identifier(&argument, source) {
                    if self.is_single_indirection_char(char_vars, &base_name) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Medium,
                            message: format!(
                                "Pointer dereference '*{}' (char type) assigned to larger type without cast to 'unsigned char' - may cause sign extension",
                                base_name
                            ),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some("Cast to 'unsigned char' before assignment: (unsigned char)*ptr".to_string()),
                            ..Default::default()
                        });
                    }
                }
            }
        }

        // Check if this is an update expression that contains a pointer dereference (*ptr++)
        if node.kind() == "update_expression" {
            if let Some(argument) = node.child_by_field_name("argument") {
                // Recursively check the argument
                self.check_pointer_dereference_in_expression(
                    &argument, source, char_vars, violations,
                );
            }
        }
    }

    /// Check subscript expressions (array indexing)
    fn check_subscript_expression(
        &self,
        node: &Node,
        source: &str,
        char_vars: &HashMap<String, (usize, bool, usize)>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(index) = node.child_by_field_name("index") {
            // Check if index is a char variable without cast to unsigned char
            if let Some(identifier) = self.extract_identifier(&index, source) {
                if char_vars.contains_key(&identifier) {
                    // Check if there's a cast to unsigned char
                    if !self.has_unsigned_char_cast(&index, source) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Medium,
                            message: format!(
                                "Array index uses '{}' (signed/plain char) without cast to 'unsigned char' - may cause negative index",
                                identifier
                            ),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some("Cast to 'unsigned char' before using as array index".to_string()),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// Check pointer expressions
    fn check_pointer_expression(
        &self,
        node: &Node,
        source: &str,
        char_vars: &HashMap<String, (usize, bool, usize)>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check if pointer dereference is of a char pointer
        if let Some(argument) = node.child_by_field_name("argument") {
            let arg_text = get_node_text(&argument, source);

            // Check if it's a char pointer variable (ends with _str, _ptr, etc. or is tracked)
            if let Some(base_name) = self.extract_identifier(&argument, source) {
                // Look for char pointer types
                if self.is_single_indirection_char(char_vars, &base_name) {
                    // Check if this dereference is being assigned to a larger type
                    if let Some(parent) = node.parent() {
                        // For `*ptr = value`, this pointer_expression is the
                        // assignment's write *target* -- the char byte is being
                        // written, not read and widened, so STR34-C's
                        // sign-extension-on-read premise doesn't apply (task 574).
                        let is_assignment_write_target = parent.kind() == "assignment_expression"
                            && parent
                                .child_by_field_name("left")
                                .is_some_and(|left| left == *node);

                        if (parent.kind() == "init_declarator"
                            || parent.kind() == "assignment_expression")
                            && !is_assignment_write_target
                        {
                            // Check if there's a cast to unsigned char
                            if !self.has_unsigned_char_cast(node, source) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::Medium,
                                    message: format!(
                                        "Pointer dereference '*{}' (char type) assigned without cast to 'unsigned char' - may cause sign extension",
                                        arg_text
                                    ),
                                    file_path: String::new(),
                                    line: node.start_position().row + 1,
                                    column: node.start_position().column + 1,
                                    suggestion: Some("Cast to 'unsigned char' before assignment to larger type".to_string()),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check cast expressions for improper casting
    fn check_cast_expression(
        &self,
        node: &Node,
        source: &str,
        char_vars: &HashMap<String, (usize, bool, usize)>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get the type being cast to
        if let Some(type_node) = node.child_by_field_name("type") {
            let type_text = get_node_text(&type_node, source);

            // Check if casting to a larger integer type (not unsigned char)
            if self.is_larger_integer_type(&type_text)
                && !type_text.contains("unsigned")
                && !type_text.contains("char")
            {
                // Get the value being cast
                if let Some(value) = node.child_by_field_name("value") {
                    // Check if the value involves a char dereference
                    if value.kind() == "pointer_expression" {
                        if let Some(argument) = value.child_by_field_name("argument") {
                            if let Some(base_name) = self.extract_identifier(&argument, source) {
                                if self.is_single_indirection_char(char_vars, &base_name) {
                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        severity: Severity::Medium,
                                        message: format!(
                                            "Cast from char pointer dereference to '{}' without intermediate cast to 'unsigned char' - may cause sign extension",
                                            type_text.trim()
                                        ),
                                        file_path: String::new(),
                                        line: node.start_position().row + 1,
                                        column: node.start_position().column + 1,
                                        suggestion: Some("Cast to 'unsigned char' before casting to larger type: (type)(unsigned char)*ptr".to_string()),
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // Also check for unsigned int/long/etc. casts from char
            if self.is_larger_integer_type(&type_text)
                && type_text.contains("unsigned")
                && !type_text.contains("char")
            {
                // Get the value being cast
                if let Some(value) = node.child_by_field_name("value") {
                    // Check if the value involves a char dereference
                    if value.kind() == "pointer_expression" {
                        if let Some(argument) = value.child_by_field_name("argument") {
                            if let Some(base_name) = self.extract_identifier(&argument, source) {
                                if self.is_single_indirection_char(char_vars, &base_name) {
                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        severity: Severity::Medium,
                                        message: format!(
                                            "Cast from char pointer dereference to '{}' without intermediate cast to 'unsigned char' - may cause sign extension",
                                            type_text.trim()
                                        ),
                                        file_path: String::new(),
                                        line: node.start_position().row + 1,
                                        column: node.start_position().column + 1,
                                        suggestion: Some("Cast to 'unsigned char' before casting to larger type: (type)(unsigned char)*ptr".to_string()),
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

    /// Check if an expression involves char variables without proper casting
    fn check_char_usage_in_expression(
        &self,
        node: &Node,
        source: &str,
        char_vars: &HashMap<String, (usize, bool, usize)>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Once a node is inside an unsigned-char cast, all its descendants are
        // too (ancestors only accumulate going down), so filtering each
        // visited node this way matches the original short-circuit exactly.
        for n in query::find_descendants(*node, |c| !self.has_unsigned_char_cast(&c, source)) {
            // Check for identifiers that are char variables
            if n.kind() == "identifier" {
                let var_name = get_node_text(&n, source);
                // char_vars only ever tracks pointer/array-typed names (see
                // collect_char_variables), so a bare identifier match here
                // would be a *pointer value* flowing into a wider integer --
                // a real type mismatch, but not the char-widening sign-
                // extension issue this branch's message describes. Gate on
                // depth 0 (never true for a tracked entry) rather than
                // deleting the dead branch outright.
                if char_vars
                    .get(var_name)
                    .is_some_and(|&(_, _, depth)| depth == 0)
                {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Medium,
                        message: format!(
                            "'{}' (signed/plain char) converted to larger integer type without cast to 'unsigned char' - may cause sign extension",
                            var_name
                        ),
                        file_path: String::new(),
                        line: n.start_position().row + 1,
                        column: n.start_position().column + 1,
                        suggestion: Some("Cast to 'unsigned char' before conversion to larger type".to_string()),
                        ..Default::default()
                    });
                }
            }

            // Check for pointer dereferences
            if n.kind() == "pointer_expression" {
                if let Some(argument) = n.child_by_field_name("argument") {
                    if let Some(base_name) = self.extract_identifier(&argument, source) {
                        if self.is_single_indirection_char(char_vars, &base_name) {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::Medium,
                                message: format!(
                                    "Pointer dereference '*{}' (char type) converted without cast to 'unsigned char' - may cause sign extension",
                                    base_name
                                ),
                                file_path: String::new(),
                                line: n.start_position().row + 1,
                                column: n.start_position().column + 1,
                                suggestion: Some("Cast to 'unsigned char' before conversion to larger type".to_string()),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    /// Check if a node has a cast to unsigned char in its ancestor chain
    fn has_unsigned_char_cast(&self, node: &Node, source: &str) -> bool {
        // Check if this node is a cast expression
        if node.kind() == "cast_expression" {
            if let Some(type_node) = node.child_by_field_name("type") {
                let type_text = get_node_text(&type_node, source);
                if type_text.contains("unsigned") && type_text.contains("char") {
                    return true;
                }
            }
        }

        // Check ancestors up the tree
        let mut current = node.parent();
        while let Some(ancestor) = current {
            if ancestor.kind() == "cast_expression" {
                if let Some(type_node) = ancestor.child_by_field_name("type") {
                    let type_text = get_node_text(&type_node, source);
                    if type_text.contains("unsigned") && type_text.contains("char") {
                        return true;
                    }
                }
            }
            current = ancestor.parent();
        }

        false
    }

    /// Check if a type is a larger integer type (int, long, size_t, etc.)
    fn is_larger_integer_type(&self, type_text: &str) -> bool {
        let trimmed = type_text.trim();

        // Check for integer types larger than char
        trimmed == "int"
            || trimmed == "long"
            || trimmed == "long int"
            || trimmed == "long long"
            || trimmed == "long long int"
            || trimmed == "unsigned int"
            || trimmed == "unsigned long"
            || trimmed == "unsigned long int"
            || trimmed == "unsigned long long"
            || trimmed == "unsigned long long int"
            || trimmed == "size_t"
            || trimmed == "ptrdiff_t"
            || trimmed == "intptr_t"
            || trimmed == "uintptr_t"
            || trimmed.contains("int32")
            || trimmed.contains("int64")
            || trimmed.contains("uint32")
            || trimmed.contains("uint64")
    }

    /// Extract identifier from a node
    fn extract_identifier(&self, node: &Node, source: &str) -> Option<String> {
        match node.kind() {
            "identifier" => Some(get_node_text(node, source).to_string()),
            "subscript_expression" => {
                if let Some(argument) = node.child_by_field_name("argument") {
                    self.extract_identifier(&argument, source)
                } else {
                    None
                }
            }
            "field_expression" => node
                .child_by_field_name("field")
                .map(|field| get_node_text(&field, source).to_string()),
            "pointer_expression" => {
                if let Some(argument) = node.child_by_field_name("argument") {
                    self.extract_identifier(&argument, source)
                } else {
                    None
                }
            }
            "update_expression" => {
                // Handle c++, ++c, c--, --c patterns
                if let Some(argument) = node.child_by_field_name("argument") {
                    self.extract_identifier(&argument, source)
                } else {
                    None
                }
            }
            "parenthesized_expression" => {
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() != "(" && child.kind() != ")" {
                            return self.extract_identifier(&child, source);
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }
}
