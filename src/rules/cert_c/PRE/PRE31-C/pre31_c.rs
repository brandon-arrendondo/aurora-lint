use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pre31C;

impl CertRule for Pre31C {
    fn rule_id(&self) -> &'static str {
        "PRE31-C"
    }

    fn description(&self) -> &'static str {
        "Avoid side effects in arguments to unsafe macros"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "PRE31-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        self.check_node(node, source, &mut violations);

        violations
    }
}

impl Pre31C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_macro_call(&call_node, source, violations);
        }
    }

    fn check_macro_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);

            // Check if this is a potentially unsafe macro
            if self.is_unsafe_macro(function_name) {
                // Skip if the macro is defined with a safe pattern (_Generic or statement expr)
                if self.is_safe_macro_definition(function_name, source) {
                    return;
                }

                let args = self.get_function_arguments(node, source);

                // Check each argument for side effects
                for (i, arg) in args.iter().enumerate() {
                    // String literals have no side effects — skip them.
                    let trimmed = arg.trim();
                    if trimmed.starts_with('"') && trimmed.ends_with('"') {
                        continue;
                    }
                    if self.has_side_effects(arg, node, source) {
                        let start_point = node.start_position();

                        let severity = if function_name == "assert" {
                            Severity::Medium // assert is disabled in release builds
                        } else {
                            Severity::High
                        };

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity,
                            message: format!(
                                "Unsafe macro '{}' called with side effect in argument {}: '{}'",
                                function_name,
                                i + 1,
                                arg
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Move side effects outside macro call or use inline function"
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    fn is_unsafe_macro(&self, function_name: &str) -> bool {
        // Fast path: safe prefix short-circuits all checks
        if function_name.starts_with("SAFE_") {
            return false;
        }

        // Check for known safe patterns (small set — use linear search)
        const SAFE_MACROS: &[&str] = &["SAFE_ABS", "SAFE_MAX", "SAFE_MIN"];
        if SAFE_MACROS.contains(&function_name) {
            return false;
        }

        // Known unsafe macros (used with linear search; this is called only when
        // is_unsafe_macro returns true in check_macro_call, which filters first)
        const UNSAFE_MACROS: &[&str] = &[
            "ABS",
            "abs",
            "MAX",
            "max",
            "MIN",
            "min",
            "assert",
            "getc",
            "putc",
            "getwc",
            "putwc",
            "SWAP",
            "swap",
            "CLAMP",
            "clamp",
            "NDEBUG",
            "DEBUG",
            "SAFE_FREE",
            "SAFE_DELETE",
            "IF_DEBUG",
            "WHEN",
            "UNLESS",
        ];

        UNSAFE_MACROS.contains(&function_name)
            || (function_name.chars().all(|c| c.is_uppercase() || c == '_')
                && function_name.len() > 2)
    }

    /// Check if the source contains a safe definition of the macro
    /// Safe definitions use _Generic or statement expressions
    fn is_safe_macro_definition(&self, function_name: &str, source: &str) -> bool {
        // Look for #define of this macro
        let define_pattern = format!("#define {}", function_name);
        if let Some(start) = source.find(&define_pattern) {
            // Get the rest of the line/definition
            let rest = &source[start..];
            // Check for safe patterns
            // _Generic evaluates its controlling expression only once
            if rest.contains("_Generic") {
                return true;
            }
            // GNU statement expression: ({ ... }) ensures single evaluation
            if rest.contains("({") {
                return true;
            }
        }
        false
    }

    /// Remove content inside string literals from an expression so that
    /// function-call patterns inside strings don't trigger false positives.
    /// e.g. `PR "mbedtls_ssl_write() timeout" PW` → `PR  PW`
    fn strip_string_literals(&self, text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let mut in_string = false;
        let mut escape_next = false;
        for ch in text.chars() {
            if escape_next {
                escape_next = false;
                continue;
            }
            if ch == '\\' && in_string {
                escape_next = true;
                continue;
            }
            if ch == '"' {
                in_string = !in_string;
                continue;
            }
            if !in_string {
                result.push(ch);
            }
        }
        result
    }

    fn has_side_effects(&self, arg: &str, context_node: &Node, source: &str) -> bool {
        // Strip string literal content to avoid false positive function-call detection
        // inside quoted text (e.g., NW_LOGE(PR "...func()..." PW, ...))
        let stripped = self.strip_string_literals(arg);
        let arg_check = stripped.as_str();

        // Check for various types of side effects in the argument

        // Direct side effect operators
        if arg_check.contains("++")
            || arg_check.contains("--")
            || arg_check.contains("+=")
            || arg_check.contains("-=")
            || arg_check.contains("*=")
            || arg_check.contains("/=")
            || arg_check.contains("%=")
            || arg_check.contains("&=")
            || arg_check.contains("|=")
            || arg_check.contains("^=")
            || arg_check.contains("<<=")
            || arg_check.contains(">>=")
        {
            return true;
        }

        // Assignment operator
        if self.contains_assignment(arg_check) {
            return true;
        }

        // Function calls that might have side effects
        if self.contains_function_call_with_side_effects(arg_check) {
            return true;
        }

        // Volatile access - check both direct keyword and via volatile variables in source
        if arg_check.contains("volatile") {
            return true;
        }
        // Check if any identifier in arg was declared as volatile in the source
        if self.is_volatile_variable_access(arg_check, source) {
            return true;
        }

        // I/O operations
        if self.contains_io_operations(arg_check) {
            return true;
        }

        // Check for more complex expressions using AST analysis
        if let Some(arg_node) = self.find_argument_node(context_node, arg, source) {
            return self.analyze_node_for_side_effects(&arg_node, source);
        }

        false
    }

    fn contains_assignment(&self, arg: &str) -> bool {
        // Look for assignment that's not part of a comparison
        let assignment_pos = arg.find('=');
        if let Some(pos) = assignment_pos {
            // Make sure it's not == or != or >= or <=
            let before = if pos > 0 {
                arg.chars().nth(pos - 1)
            } else {
                None
            };
            let after = arg.chars().nth(pos + 1);

            !matches!(
                (before, after),
                (Some('!' | '=' | '<' | '>'), _) | (_, Some('='))
            )
        } else {
            false
        }
    }

    fn contains_function_call_with_side_effects(&self, arg: &str) -> bool {
        // Known functions that have side effects
        let side_effect_functions = [
            "printf", "fprintf", "sprintf", "scanf", "fscanf", "sscanf", "malloc", "calloc",
            "realloc", "free", "fopen", "fclose", "fread", "fwrite", "fgetc", "fputc", "getchar",
            "putchar", "gets", "puts", "rand", "srand", "time", "exit", "abort", "system",
            // String functions that may have side effects (modify errno, etc.)
            "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strcat", "strncat", "strtok",
            "strtol", "strtoul", "strtod", "atoi", "atol", "atof",
            // Memory functions
            "memcpy", "memmove", "memset", "memcmp",
        ];

        for func in &side_effect_functions {
            if arg.contains(&format!("{}(", func)) {
                return true;
            }
        }

        // Also check for any function call pattern: identifier followed by (
        // This catches user-defined functions that might have side effects
        self.contains_any_function_call(arg)
    }

    fn contains_any_function_call(&self, arg: &str) -> bool {
        // Look for function call pattern: identifier(
        // But exclude known safe operations like type casts and pure functions
        let chars: Vec<char> = arg.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            // Look for open paren
            if chars[i] == '(' {
                // Look backwards for identifier
                let mut end = i;
                // Skip whitespace
                while end > 0 && chars[end - 1].is_whitespace() {
                    end -= 1;
                }
                // Check if there's an identifier before the paren
                let mut start = end;
                while start > 0 && (chars[start - 1].is_alphanumeric() || chars[start - 1] == '_') {
                    start -= 1;
                }
                if start < end {
                    let identifier: String = chars[start..end].iter().collect();
                    // Filter out known safe constructs (type casts, sizeof, etc.)
                    let safe_patterns = [
                        "int",
                        "char",
                        "float",
                        "double",
                        "long",
                        "short",
                        "unsigned",
                        "signed",
                        "void",
                        "size_t",
                        "sizeof",
                        "typeof",
                        "__typeof__",
                    ];
                    // Pure functions that have no side effects (PRE31-C-EX1)
                    // These functions only compute a value from their inputs
                    let pure_functions = [
                        "abs",
                        "labs",
                        "llabs",
                        "fabs",
                        "fabsf",
                        "fabsl",
                        "sqrt",
                        "sqrtf",
                        "sqrtl",
                        "cbrt",
                        "cbrtf",
                        "cbrtl",
                        "sin",
                        "cos",
                        "tan",
                        "asin",
                        "acos",
                        "atan",
                        "atan2",
                        "sinh",
                        "cosh",
                        "tanh",
                        "asinh",
                        "acosh",
                        "atanh",
                        "exp",
                        "exp2",
                        "expm1",
                        "log",
                        "log2",
                        "log10",
                        "log1p",
                        "pow",
                        "hypot",
                        "ceil",
                        "floor",
                        "round",
                        "trunc",
                        "fmod",
                        "remainder",
                        "fmax",
                        "fmin",
                        "isnan",
                        "isinf",
                        "isfinite",
                        "isnormal",
                        "square", // Common user-defined pure function
                        "negate",
                        "negative",
                        "positive",
                    ];
                    if !safe_patterns.contains(&identifier.as_str())
                        && !identifier.starts_with("_Generic")
                        && !pure_functions.contains(&identifier.as_str())
                    {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn contains_io_operations(&self, arg: &str) -> bool {
        // Look for I/O related operations
        arg.contains("printf")
            || arg.contains("scanf")
            || arg.contains("getc")
            || arg.contains("putc")
            || arg.contains("fread")
            || arg.contains("fwrite")
            || arg.contains("cout")
            || arg.contains("cin") // C++ style I/O
    }

    fn find_argument_node<'a>(
        &self,
        call_node: &'a Node<'a>,
        arg_text: &str,
        source: &str,
    ) -> Option<Node<'a>> {
        // Try to find the AST node corresponding to this argument
        if let Some(arguments) = call_node.child_by_field_name("arguments") {
            for i in 0..arguments.child_count() {
                if let Some(child) = arguments.child(i) {
                    if child.kind() != "," {
                        let node_text = get_node_text(&child, source);
                        if node_text.trim() == arg_text.trim() {
                            return Some(child);
                        }
                    }
                }
            }
        }
        None
    }

    fn analyze_node_for_side_effects(&self, node: &Node, source: &str) -> bool {
        match node.kind() {
            "update_expression" => true,     // ++, --
            "assignment_expression" => true, // =, +=, etc.
            "call_expression" => {
                // Check if it's a function call that might have side effects
                if let Some(func_node) = node.child_by_field_name("function") {
                    let func_name = get_node_text(&func_node, source);
                    self.contains_function_call_with_side_effects(func_name)
                } else {
                    false
                }
            }
            _ => {
                // Recursively check child nodes
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if self.analyze_node_for_side_effects(&child, source) {
                            return true;
                        }
                    }
                }
                false
            }
        }
    }

    fn get_function_arguments(&self, node: &Node, source: &str) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(arguments) = node.child_by_field_name("arguments") {
            for i in 0..arguments.child_count() {
                if let Some(child) = arguments.child(i) {
                    if child.kind() != "," {
                        let arg_text = get_node_text(&child, source).to_string();
                        args.push(arg_text.trim().to_string());
                    }
                }
            }
        }

        args
    }

    /// Check if the argument contains access to a volatile variable
    fn is_volatile_variable_access(&self, arg: &str, source: &str) -> bool {
        // Extract identifiers from the argument
        let identifiers = self.extract_identifiers(arg);

        // Check if any identifier is declared as volatile in the source
        for id in identifiers {
            // Look for volatile declaration of this variable
            // Patterns: "volatile int name" or "volatile type name" or "type volatile name"
            let _patterns = [
                format!("volatile {} {};", id, ""), // At start
                format!("volatile {}", id),         // Basic pattern
                format!("{} volatile", id),         // Type after volatile
            ];

            // Simple check: look for "volatile" followed by the identifier or identifier preceded by volatile
            if source.contains(&format!("volatile int {}", id))
                || source.contains(&format!("volatile unsigned {}", id))
                || source.contains(&format!("volatile char {}", id))
                || source.contains(&format!("volatile short {}", id))
                || source.contains(&format!("volatile long {}", id))
                || source.contains(&format!("int volatile {}", id))
                || source.contains(&format!("volatile {}", id))
            {
                return true;
            }
        }
        false
    }

    /// Extract all identifiers from an expression
    fn extract_identifiers(&self, expr: &str) -> Vec<String> {
        let mut identifiers = Vec::new();
        let chars: Vec<char> = expr.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            // Look for start of identifier
            if chars[i].is_alphabetic() || chars[i] == '_' {
                let start = i;
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let id: String = chars[start..i].iter().collect();
                // Filter out keywords
                let keywords = [
                    "if", "else", "while", "for", "return", "int", "char", "void", "float",
                    "double", "long", "short", "unsigned", "signed", "const", "volatile", "static",
                    "extern", "sizeof",
                ];
                if !keywords.contains(&id.as_str()) {
                    identifiers.push(id);
                }
            } else {
                i += 1;
            }
        }
        identifiers
    }
}
