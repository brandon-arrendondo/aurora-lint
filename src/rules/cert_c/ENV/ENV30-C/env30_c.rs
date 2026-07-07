use crate::manifest::{RuleCategory, Severity};
use crate::prelude::RuleViolation;
use crate::rules::cert_c::CertRule;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct ENV30C;

impl CertRule for ENV30C {
    fn rule_id(&self) -> &'static str {
        "ENV30-C"
    }

    fn cert_id(&self) -> &'static str {
        "ENV30"
    }

    fn description(&self) -> &'static str {
        "Do not modify the object referenced by the return value of certain functions"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl ENV30C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check function definitions to track variable assignments from protected functions
        for n in query::find_descendants_of_kind(*node, "function_definition") {
            violations.extend(self.check_function_for_violations(&n, source));
        }
    }

    fn check_function_for_violations(&self, func_node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let mut protected_vars: HashMap<String, String> = HashMap::new();

        // Collect all variable assignments from protected functions
        self.collect_protected_assignments(func_node, source, &mut protected_vars);

        // Check for modifications to those variables
        self.check_protected_var_modifications(func_node, source, &protected_vars, &mut violations);

        violations
    }

    fn collect_protected_assignments(
        &self,
        node: &Node,
        source: &str,
        protected_vars: &mut HashMap<String, String>,
    ) {
        for n in query::find_descendants(*node, |_| true) {
            // Look for declarations like: char *env = getenv("X");
            if n.kind() == "declaration" {
                let text = get_node_text(&n, source);
                // Find if there's a protected function call
                if let Some(func_name) = self.find_protected_function_in_text(&text) {
                    // Extract variable name
                    if let Some(var_name) = self.extract_var_name_from_declaration(&n, source) {
                        protected_vars.insert(var_name, func_name);
                    }
                }
                // Also check for derived pointers: char *ptr = strchr(protected_var, '.')
                else if let Some((derived_var, orig_func)) =
                    self.check_derived_pointer_declaration(&n, source, protected_vars)
                {
                    protected_vars.insert(derived_var, format!("{} (derived)", orig_func));
                }
            }

            // Also handle assignment expressions (reassignment)
            if n.kind() == "assignment_expression" {
                let text = get_node_text(&n, source);
                if let Some(func_name) = self.find_protected_function_in_text(&text) {
                    // Extract variable name from left side
                    if let Some(left) = n.child_by_field_name("left") {
                        let var_name = get_node_text(&left, source).trim().to_string();
                        if !var_name.is_empty() {
                            protected_vars.insert(var_name, func_name);
                        }
                    }
                }
                // Also check for derived pointers
                else if let Some((derived_var, orig_func)) =
                    self.check_derived_pointer_assignment(&n, source, protected_vars)
                {
                    protected_vars.insert(derived_var, format!("{} (derived)", orig_func));
                }
                // Check for pointer aliasing: p = protected_var
                else if let Some((alias_var, orig_func)) =
                    self.check_pointer_alias(&n, source, protected_vars)
                {
                    protected_vars.insert(alias_var, format!("{} (alias)", orig_func));
                }
            }

            // Handle pointer aliases in init_declarator: char *p = protected_var
            if n.kind() == "init_declarator" {
                if let Some((alias_var, orig_func)) =
                    self.check_init_declarator_alias(&n, source, protected_vars)
                {
                    protected_vars.insert(alias_var, format!("{} (alias)", orig_func));
                }
            }
        }
    }

    /// Check if this declaration creates a derived pointer from a protected variable
    /// e.g., char *dot = strchr(lang, '.') where lang is protected
    fn check_derived_pointer_declaration(
        &self,
        node: &Node,
        source: &str,
        protected_vars: &HashMap<String, String>,
    ) -> Option<(String, String)> {
        let text = get_node_text(node, source);

        // Check for pointer-returning string functions
        let pointer_funcs = ["strchr", "strrchr", "strstr", "strpbrk", "memchr"];

        for func in &pointer_funcs {
            if text.contains(&format!("{}(", func)) {
                // Extract the variable name from the declaration
                if let Some(var_name) = self.extract_var_name_from_declaration(node, source) {
                    // Check if any protected variable is used as the first argument
                    for (prot_var, orig_func) in protected_vars.iter() {
                        // Use word boundary matching to avoid substring false positives
                        // e.g., "lang" should not match "lang_copy"
                        if self.is_protected_var_in_call(&text, func, prot_var) {
                            return Some((var_name, orig_func.clone()));
                        }
                    }
                }
            }
        }
        None
    }

    /// Check if a protected variable is used as the first argument in a function call
    /// Uses word boundary checking to avoid substring matches
    fn is_protected_var_in_call(&self, text: &str, func: &str, var_name: &str) -> bool {
        // Look for pattern: func(var_name followed by , or )
        let pattern_comma = format!("{}({},", func, var_name);
        let pattern_paren = format!("{}({})", func, var_name);
        let pattern_space_comma = format!("{}({} ,", func, var_name);
        let pattern_space_paren = format!("{}({} )", func, var_name);

        if text.contains(&pattern_comma)
            || text.contains(&pattern_paren)
            || text.contains(&pattern_space_comma)
            || text.contains(&pattern_space_paren)
        {
            return true;
        }

        // Also check with whitespace after opening paren
        let pattern_ws_comma = format!("{}( {},", func, var_name);
        let pattern_ws_paren = format!("{}( {})", func, var_name);
        if text.contains(&pattern_ws_comma) || text.contains(&pattern_ws_paren) {
            return true;
        }

        false
    }

    /// Check if this assignment creates a derived pointer from a protected variable
    fn check_derived_pointer_assignment(
        &self,
        node: &Node,
        source: &str,
        protected_vars: &HashMap<String, String>,
    ) -> Option<(String, String)> {
        let text = get_node_text(node, source);

        let pointer_funcs = ["strchr", "strrchr", "strstr", "strpbrk", "memchr"];

        for func in &pointer_funcs {
            if text.contains(&format!("{}(", func)) {
                // Extract variable name from left side
                if let Some(left) = node.child_by_field_name("left") {
                    let var_name = get_node_text(&left, source).trim().to_string();
                    // Check if any protected variable is used as the first argument
                    for (prot_var, orig_func) in protected_vars.iter() {
                        // Use word boundary matching to avoid substring false positives
                        if self.is_protected_var_in_call(&text, func, prot_var) {
                            return Some((var_name, orig_func.clone()));
                        }
                    }
                }
            }
        }
        None
    }

    /// Check if assignment is a direct pointer alias: alias = protected_var
    fn check_pointer_alias(
        &self,
        node: &Node,
        source: &str,
        protected_vars: &HashMap<String, String>,
    ) -> Option<(String, String)> {
        if let Some(left) = node.child_by_field_name("left") {
            if let Some(right) = node.child_by_field_name("right") {
                let right_text = get_node_text(&right, source).trim().to_string();
                // Check if right side is a protected variable (direct assignment)
                if let Some(orig_func) = protected_vars.get(&right_text) {
                    let alias_name = get_node_text(&left, source).trim().to_string();
                    if !alias_name.is_empty() && alias_name != right_text {
                        return Some((alias_name, orig_func.clone()));
                    }
                }
            }
        }
        None
    }

    /// Check if init_declarator creates an alias: char *p = protected_var
    fn check_init_declarator_alias(
        &self,
        node: &Node,
        source: &str,
        protected_vars: &HashMap<String, String>,
    ) -> Option<(String, String)> {
        // Look for value field (the initializer)
        if let Some(value) = node.child_by_field_name("value") {
            let value_text = get_node_text(&value, source).trim().to_string();
            // Check if value is a protected variable
            if let Some(orig_func) = protected_vars.get(&value_text) {
                // Get the variable name being declared
                if let Some(decl) = node.child_by_field_name("declarator") {
                    let alias_name = self.extract_identifier_from_declarator(&decl, source);
                    if !alias_name.is_empty() && alias_name != value_text {
                        return Some((alias_name, orig_func.clone()));
                    }
                }
            }
        }
        None
    }

    fn find_protected_function_in_text(&self, text: &str) -> Option<String> {
        let protected_funcs = [
            "getenv",
            "localeconv",
            "setlocale",
            "strerror",
            "asctime",
            "ctime",
            "gmtime",
            "localtime",
            "getdate",
            "getlogin",
        ];

        for func in &protected_funcs {
            // Look for func( pattern
            if text.contains(&format!("{}(", func)) {
                return Some(func.to_string());
            }
        }
        None
    }

    fn extract_var_name_from_declaration(&self, node: &Node, source: &str) -> Option<String> {
        // Look for init_declarator nodes
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "init_declarator" {
                // Find the declarator (could be pointer_declarator or identifier)
                if let Some(decl) = child.child_by_field_name("declarator") {
                    return Some(self.extract_identifier_from_declarator(&decl, source));
                }
            }
        }
        None
    }

    fn extract_identifier_from_declarator(&self, node: &Node, source: &str) -> String {
        if node.kind() == "identifier" {
            return get_node_text(node, source).to_string();
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            let id = self.extract_identifier_from_declarator(&child, source);
            if !id.is_empty() {
                return id;
            }
        }

        String::new()
    }

    fn check_protected_var_modifications(
        &self,
        node: &Node,
        source: &str,
        protected_vars: &HashMap<String, String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants(*node, |_| true) {
            // Check for assignments that modify memory pointed to by protected variables
            if n.kind() == "assignment_expression" {
                if let Some(left) = n.child_by_field_name("left") {
                    // Only flag modifications through the pointer, not reassignment of the pointer itself
                    // e.g., `env[0] = 'X'` or `*env = 'X'` or `conv->field = x` should flag
                    // but `env = something_else` should NOT flag (that's just reassigning the pointer)
                    let left_kind = left.kind();
                    if left_kind == "subscript_expression"
                        || left_kind == "pointer_expression"
                        || left_kind == "field_expression"
                    {
                        if let Some((var_name, func_name)) =
                            self.get_protected_var_ref(&left, source, protected_vars)
                        {
                            let start = n.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                file_path: String::new(),
                                message: format!(
                                    "Modifying memory referenced by '{}' which holds return value from '{}()'. The return value should not be modified.",
                                    var_name, func_name
                                ),
                                line: start.row + 1,
                                column: start.column + 1,
                                severity: self.severity(),
                                suggestion: Some(
                                    "Copy the return value to a local buffer before modifying it"
                                        .to_string(),
                                ),
                                requires_manual_review: Some(false),
                            });
                        }
                    }
                }
            }

            // Check for calls that might modify protected variables
            if n.kind() == "call_expression" {
                self.check_call_for_modification(&n, source, protected_vars, violations);
            }
        }
    }

    fn check_call_for_modification(
        &self,
        node: &Node,
        source: &str,
        protected_vars: &HashMap<String, String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get function name
        let func_name = if let Some(func_node) = node.child_by_field_name("function") {
            get_node_text(&func_node, source).to_string()
        } else {
            return;
        };

        // Get argument list
        if let Some(args) = node.child_by_field_name("arguments") {
            let mut cursor = args.walk();
            let arg_list: Vec<_> = args
                .children(&mut cursor)
                .filter(|c| c.kind() != "(" && c.kind() != ")" && c.kind() != ",")
                .collect();

            // For modification functions, check ONLY the first argument (destination)
            // The second argument (source) is safe to be a protected variable
            if self.is_modification_function(&func_name) {
                if let Some(first_arg) = arg_list.first() {
                    if let Some((var_name, orig_func)) =
                        self.get_protected_var_ref(first_arg, source, protected_vars)
                    {
                        let start = node.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            file_path: String::new(),
                            message: format!(
                                "Passing variable '{}' (from '{}()') as destination to modification function '{}()'.",
                                var_name, orig_func, func_name
                            ),
                            line: start.row + 1,
                            column: start.column + 1,
                            severity: self.severity(),
                            suggestion: Some(
                                "Copy the return value to a local buffer before passing as destination to modification functions"
                                    .to_string(),
                            ),
                            requires_manual_review: Some(false),
                        });
                    }
                }
            } else if !self.is_safe_function(&func_name)
                && !self.is_protected_function(&func_name)
                && !self.is_pointer_returning_function(&func_name)
            {
                // For unknown user-defined functions, check if a protected variable
                // is passed as the first argument (which could be modified)
                if let Some(first_arg) = arg_list.first() {
                    if let Some((var_name, orig_func)) =
                        self.get_protected_var_ref(first_arg, source, protected_vars)
                    {
                        let start = node.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            file_path: String::new(),
                            message: format!(
                                "Passing variable '{}' (from '{}()') to function '{}()' which may modify it.",
                                var_name, orig_func, func_name
                            ),
                            line: start.row + 1,
                            column: start.column + 1,
                            severity: self.severity(),
                            suggestion: Some(
                                "Copy the return value to a local buffer before passing to functions that may modify it"
                                    .to_string(),
                            ),
                            requires_manual_review: Some(true),
                        });
                    }
                }
            }
        }
    }

    fn get_protected_var_ref(
        &self,
        node: &Node,
        source: &str,
        protected_vars: &HashMap<String, String>,
    ) -> Option<(String, String)> {
        match node.kind() {
            "identifier" => {
                let name = get_node_text(node, source);
                if let Some(func_name) = protected_vars.get(name) {
                    return Some((name.to_string(), func_name.clone()));
                }
            }
            "subscript_expression" => {
                // Check if the array base is a protected variable (e.g., env[0])
                if let Some(array) = node.child_by_field_name("argument") {
                    return self.get_protected_var_ref(&array, source, protected_vars);
                }
                // Also try first child for tree-sitter variations
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if let Some(result) = self.get_protected_var_ref(&child, source, protected_vars)
                    {
                        return Some(result);
                    }
                }
            }
            "pointer_expression" => {
                // Dereference: *ptr
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if let Some(result) = self.get_protected_var_ref(&child, source, protected_vars)
                    {
                        return Some(result);
                    }
                }
            }
            "field_expression" => {
                // Field access: conv->decimal_point
                if let Some(argument) = node.child_by_field_name("argument") {
                    return self.get_protected_var_ref(&argument, source, protected_vars);
                }
            }
            _ => {
                // Recurse into children for complex expressions
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if let Some(result) = self.get_protected_var_ref(&child, source, protected_vars)
                    {
                        return Some(result);
                    }
                }
            }
        }

        None
    }

    fn is_modification_function(&self, name: &str) -> bool {
        matches!(
            name,
            "strcpy"
                | "strncpy"
                | "strcat"
                | "strncat"
                | "sprintf"
                | "snprintf"
                | "memcpy"
                | "memmove"
                | "memset"
                | "strtok"
                | "gets"
                | "fgets"
        )
    }

    fn is_safe_function(&self, name: &str) -> bool {
        // Pattern-based safe function detection for copy-like functions
        let name_lower = name.to_lowercase();
        if name_lower.contains("copy")
            || name_lower.contains("dup")
            || name_lower.contains("clone")
            || name_lower.ends_with("_safe")
            || name_lower.starts_with("safe_")
        {
            return true;
        }

        // Functions that don't modify their first argument (may read it but not write)
        matches!(
            name,
            // Output functions (read string, output elsewhere)
            "printf"
                | "fprintf"
                | "sprintf"
                | "snprintf"
                | "puts"
                | "fputs"
                | "fwrite"
                | "write"
                // String examination functions
                | "strlen"
                | "strcmp"
                | "strncmp"
                | "strchr"
                | "strrchr"
                | "strstr"
                | "strspn"
                | "strcspn"
                // String duplication (makes a copy, doesn't modify original)
                | "strdup"
                | "strndup"
                // Conversion functions (read string)
                | "atoi"
                | "atol"
                | "atof"
                | "strtol"
                | "strtoul"
                | "strtod"
                | "strtoll"
                | "strtoull"
                // Parsing/scanning
                | "sscanf"
                // Memory allocation
                | "free"
                | "malloc"
                | "calloc"
                | "realloc"
                // File operations (read path string)
                | "open"
                | "fopen"
                | "stat"
                | "lstat"
                | "access"
                | "unlink"
                | "remove"
                | "rename"
                | "mkdir"
                | "rmdir"
                | "chdir"
                | "opendir"
                // Logging/error handling
                | "perror"
                | "syslog"
                | "log_message"
                // Comparison and search
                | "memcmp"
                | "bsearch"
        )
    }

    fn is_protected_function(&self, name: &str) -> bool {
        matches!(
            name,
            "getenv"
                | "localeconv"
                | "setlocale"
                | "strerror"
                | "asctime"
                | "ctime"
                | "gmtime"
                | "localtime"
                | "getdate"
                | "getlogin"
        )
    }

    fn is_pointer_returning_function(&self, name: &str) -> bool {
        // Functions that return pointers into protected data but are not themselves protected
        matches!(name, "strchr" | "strrchr" | "strstr" | "strpbrk" | "memchr")
    }
}
