use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Pre32C;

/// Information about an unclosed function call
struct UnclosedCallInfo {
    function_name: String,
    open_parens: usize,
}

impl CertRule for Pre32C {
    fn rule_id(&self) -> &'static str {
        "PRE32-C"
    }

    fn description(&self) -> &'static str {
        "Do not use preprocessor directives in invocations of function-like macros"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "PRE32-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        self.check_node(node, source, &mut violations);

        violations
    }
}

impl Pre32C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        const KINDS: &[&str] = &[
            "call_expression",
            "preproc_ifdef",
            "preproc_if",
            "preproc_ifndef",
            "preproc_else",
            "preproc_elif",
            "preproc_call",
            "preproc_def",
            "preproc_include",
        ];
        for n in query::find_descendants_of_kinds(*node, KINDS) {
            match n.kind() {
                "call_expression" => {
                    self.check_function_call(&n, source, violations);
                }
                // Check for preprocessor directives that contain call expressions
                // This catches cases where tree-sitter parses the #ifdef as a wrapper
                "preproc_ifdef" | "preproc_if" | "preproc_ifndef" | "preproc_else"
                | "preproc_elif" | "preproc_call" | "preproc_def" | "preproc_include" => {
                    self.check_preproc_for_macro_calls(&n, source, violations);
                }
                _ => {}
            }
        }
    }

    /// Check if a preprocessor directive (like #ifdef) appears within a macro call
    /// by looking at the raw source text around the directive
    fn check_preproc_for_macro_calls(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let start_byte = node.start_byte();
        let _end_byte = node.end_byte();

        // Look backwards from the preprocessor directive to find an unclosed call expression
        // We need to check if there's an open parenthesis for a function call that spans this directive
        let text_before = &source[..start_byte];

        // Find the last function call that might contain this directive
        // Look for pattern like "func(" or "MACRO("
        if let Some(call_info) = self.find_unclosed_call_before(text_before) {
            // Now check if the call closes after this preprocessor directive
            // Note: For preproc_ifdef/preproc_if/etc., the node spans the entire block (from #ifdef to #endif)
            // So we need to check what's after the START of the directive, not the END
            // This means we look at whether there's a closing paren somewhere after the directive starts
            let text_after_start = &source[start_byte..];
            if self.has_matching_close_paren(text_after_start, call_info.open_parens) {
                // This preprocessor directive is inside a function/macro call
                let start_point = node.start_position();
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Preprocessor directive '{}' used inside invocation of '{}'. This causes undefined behavior if the function is implemented as a macro",
                        node.kind().replace("preproc_", "#"),
                        call_info.function_name
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Move preprocessor directives outside the function call using conditional compilation".to_string()),
                    ..Default::default()
                });
            }
        }
    }

    /// Find an unclosed function call before the given position
    fn find_unclosed_call_before(&self, text: &str) -> Option<UnclosedCallInfo> {
        let mut paren_depth = 0i32;
        let chars: Vec<char> = text.chars().collect();
        let mut i = chars.len();

        // Scan backwards
        while i > 0 {
            i -= 1;
            match chars[i] {
                ')' => paren_depth += 1,
                '(' => {
                    paren_depth -= 1;
                    if paren_depth < 0 {
                        // Found unclosed open paren - look for function name
                        let mut end = i;
                        // Skip whitespace
                        while end > 0 && chars[end - 1].is_whitespace() {
                            end -= 1;
                        }
                        // Extract identifier
                        let mut start = end;
                        while start > 0
                            && (chars[start - 1].is_alphanumeric() || chars[start - 1] == '_')
                        {
                            start -= 1;
                        }
                        if start < end {
                            let function_name: String = chars[start..end].iter().collect();
                            if self.is_potentially_macro_function(&function_name) {
                                return Some(UnclosedCallInfo {
                                    function_name,
                                    open_parens: (-paren_depth) as usize,
                                });
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Check if there's a matching close paren for the unclosed call
    fn has_matching_close_paren(&self, text: &str, open_count: usize) -> bool {
        let mut close_count = 0usize;
        let mut paren_depth = 0i32;

        for c in text.chars() {
            match c {
                '(' => paren_depth += 1,
                ')' => {
                    if paren_depth > 0 {
                        paren_depth -= 1;
                    } else {
                        close_count += 1;
                        if close_count >= open_count {
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn check_function_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = &source[function_node.start_byte()..function_node.end_byte()];

            // Check if this is a potentially macro-implemented function
            if self.is_potentially_macro_function(function_name) {
                // Check arguments for preprocessor directives
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    self.check_arguments_for_directives(
                        &arguments,
                        source,
                        function_name,
                        violations,
                    );
                }
            }
        }
    }

    fn check_arguments_for_directives(
        &self,
        arguments: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get the full text of the arguments section
        let args_text = &source[arguments.start_byte()..arguments.end_byte()];

        // Look for preprocessor directives within the arguments
        if self.contains_preprocessor_directives(args_text) {
            let start_point = arguments.start_position();

            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Function '{}' called with preprocessor directives in arguments. This causes undefined behavior if the function is implemented as a macro",
                    function_name
                ),
                file_path: String::new(),
                line: start_point.row + 1,
                column: start_point.column + 1,
                suggestion: Some("Move preprocessor directives outside the function call using conditional compilation".to_string()),
            ..Default::default()
            });
        }

        // Also check individual arguments
        for i in 0..arguments.child_count() {
            if let Some(child) = arguments.child(i) {
                if child.kind() != "," {
                    let arg_text = &source[child.start_byte()..child.end_byte()];
                    if self.contains_preprocessor_directives(arg_text) {
                        let start_point = child.start_position();

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::High,
                            message: format!(
                                "Argument to '{}' contains preprocessor directive: '{}'",
                                function_name,
                                arg_text.trim()
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Use conditional compilation to wrap the entire function call"
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    fn is_potentially_macro_function(&self, function_name: &str) -> bool {
        // Standard library functions that may be implemented as macros
        let std_lib_functions: HashSet<&str> = [
            // String functions
            "memcpy", "memmove", "memset", "memcmp", "memchr", "strcpy", "strncpy", "strcat",
            "strncat", "strcmp", "strncmp", "strchr", "strrchr", "strpbrk", "strspn", "strcspn",
            "strstr", "strtok", "strlen", // Character functions
            "isalnum", "isalpha", "isblank", "iscntrl", "isdigit", "isgraph", "islower", "isprint",
            "ispunct", "isspace", "isupper", "isxdigit", "tolower", "toupper",
            // I/O functions
            "getc", "putc", "getchar", "putchar", "fgetc", "fputc", "getwc", "putwc", "fgetwc",
            "fputwc", "printf", "fprintf", "sprintf", "snprintf", "scanf", "fscanf", "sscanf",
            "fread", "fwrite", "fopen", "fclose", "fseek", "ftell", "rewind", "fgets", "fputs",
            // Math functions
            "abs", "labs", "llabs", "fabs", "fabsf", "fabsl", "sqrt", "sqrtf", "sqrtl", "pow",
            "powf", "powl", "sin", "cos", "tan", "asin", "acos", "atan", "atan2", "exp", "log",
            "log10", "ceil", "floor", "fmod", // Memory allocation
            "malloc", "calloc", "realloc", "free",   // Assertion
            "assert", // Wide character functions
            "wmemcpy", "wmemmove", "wmemset", "wmemcmp", "wmemchr", "wcscpy", "wcsncpy", "wcscat",
            "wcsncat", "wcscmp", "wcsncmp", "wcschr", "wcsrchr", "wcspbrk", "wcsspn", "wcscspn",
            "wcsstr", "wcstok", "wcslen",
        ]
        .iter()
        .cloned()
        .collect();

        std_lib_functions.contains(function_name) ||
        // Any function could potentially be a macro, so we should be conservative
        // But focus on functions commonly implemented as macros
        function_name.chars().all(|c| c.is_uppercase() || c == '_' || c.is_ascii_digit())
        // ALL_CAPS suggests macro
    }

    fn contains_preprocessor_directives(&self, text: &str) -> bool {
        // Look for preprocessor directive patterns
        let directives = [
            "#define", "#undef", "#include", "#if", "#ifdef", "#ifndef", "#else", "#elif",
            "#endif", "#error", "#warning", "#pragma", "#line",
        ];

        for directive in &directives {
            if text.contains(directive) {
                return true;
            }
        }

        // Also look for macro continuation patterns
        if text.contains("\\") && text.contains("\n") {
            return true;
        }

        false
    }

    #[allow(dead_code)]
    fn spans_multiple_lines_with_directives(&self, text: &str) -> bool {
        let lines: Vec<&str> = text.lines().collect();

        if lines.len() <= 1 {
            return false;
        }

        // Check if any line contains preprocessor directives
        for line in lines {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                return true;
            }
        }

        false
    }
}
