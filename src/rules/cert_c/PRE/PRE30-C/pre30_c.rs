use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pre30C;

impl CertRule for Pre30C {
    fn rule_id(&self) -> &'static str {
        "PRE30-C"
    }

    fn description(&self) -> &'static str {
        "Do not create a universal character name through concatenation"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "PRE30-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First, do text-based scanning for UCN fragments
        self.check_source_for_ucn_fragments(source, &mut violations);

        // Then do AST-based checks
        self.check_node(node, source, &mut violations);

        violations
    }
}

impl Pre30C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in
            query::find_descendants_of_kinds(*node, &["preproc_function_def", "call_expression"])
        {
            match n.kind() {
                "preproc_function_def" => {
                    self.check_macro_definition(&n, source, violations);
                }
                "call_expression" => {
                    self.check_macro_invocation(&n, source, violations);
                }
                _ => {}
            }
        }
    }

    fn check_macro_definition(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let macro_text = get_node_text(node, source);

        // Look for token concatenation (##) that might create universal character names
        if macro_text.contains("##") {
            // Extract macro parameters
            let params = self.extract_macro_params(node, source);

            // Check if ## concatenates parameters AND parameters suggest UCN usage
            if self.concatenates_params(&macro_text, &params) {
                let start_point = node.start_position();

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: "Macro definition uses token concatenation (##) between parameters which may create universal character names, leading to undefined behavior".to_string(),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Avoid token concatenation that creates universal character names (\\uXXXX or \\UXXXXXXXX). Use complete UCN identifiers instead.".to_string()),
                ..Default::default()
                });
            }

            // Also check for UCN patterns directly in the macro body (e.g., \u##XX patterns)
            if self.contains_potential_ucn_concatenation(&macro_text) {
                let start_point = node.start_position();

                // Avoid duplicate if already reported
                if violations.iter().all(|v| v.line != start_point.row + 1) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: "Macro definition contains UCN pattern with token concatenation that may create universal character names".to_string(),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some("Avoid token concatenation that creates universal character names (\\uXXXX or \\UXXXXXXXX)".to_string()),
                    ..Default::default()
                    });
                }
            }
        }
    }

    /// Extract parameter names from macro definition
    fn extract_macro_params(&self, node: &Node, source: &str) -> Vec<String> {
        let mut params = Vec::new();

        // Find the parameters field
        if let Some(params_node) = node.child_by_field_name("parameters") {
            let params_text = get_node_text(&params_node, source);
            // Parse "(param1, param2, ...)" format
            let inner = params_text.trim_start_matches('(').trim_end_matches(')');
            for param in inner.split(',') {
                let param = param.trim();
                if !param.is_empty() {
                    params.push(param.to_string());
                }
            }
        }

        params
    }

    /// Check if the macro body concatenates parameters that suggest UCN usage
    fn concatenates_params(&self, macro_text: &str, params: &[String]) -> bool {
        // Look for patterns like "param1##param2" or "param1 ## param2"
        let parts: Vec<&str> = macro_text.split("##").collect();

        if parts.len() < 2 {
            return false;
        }

        for window in parts.windows(2) {
            let left = window[0].trim();
            let right = window[1].trim();

            // Get the last word from left part and first word from right part
            let left_word = left.split_whitespace().last().unwrap_or("");
            let right_word = right.split_whitespace().next().unwrap_or("");

            // Remove any trailing/leading special chars
            let left_word = left_word.trim_end_matches(|c: char| !c.is_alphanumeric() && c != '_');
            let right_word =
                right_word.trim_start_matches(|c: char| !c.is_alphanumeric() && c != '_');

            // Check if both sides are parameters
            let left_is_param = params.iter().any(|p| p == left_word);
            let right_is_param = params.iter().any(|p| p == right_word);

            if left_is_param && right_is_param {
                // Check if parameter names suggest UCN usage
                // This helps distinguish between normal concat macros and UCN-specific ones
                if self.params_suggest_ucn(left_word, right_word) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if parameter names suggest UCN usage
    fn params_suggest_ucn(&self, p1: &str, p2: &str) -> bool {
        let p1_lower = p1.to_lowercase();
        let p2_lower = p2.to_lowercase();

        // Check for UCN-suggesting patterns
        // uc1, uc2, ucn, etc.
        let ucn_patterns = ["uc", "ucn", "char"];

        for pattern in ucn_patterns {
            if p1_lower.contains(pattern) || p2_lower.contains(pattern) {
                return true;
            }
        }

        // Also flag if they're numbered pairs like v1/v2 since these are often used for UCN parts
        // But this is too broad - let's be more conservative

        false
    }

    fn check_macro_invocation(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check for macro calls that might involve UCN concatenation
        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);

            // Get the arguments to check for UCN patterns
            let args = self.get_macro_arguments(node, source);

            // Look for patterns where UCN fragments might be concatenated
            if self.has_ucn_concatenation_pattern(&args, function_name) {
                let start_point = node.start_position();

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Macro invocation '{}' may create universal character names through concatenation",
                        function_name
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some("Use complete universal character names instead of concatenating fragments".to_string()),
                ..Default::default()
                });
            }
        }
    }

    fn contains_potential_ucn_concatenation(&self, macro_text: &str) -> bool {
        // Look for patterns that suggest UCN concatenation
        // Examples: uc1##uc2, \u##04, etc.

        // Check for partial UCN patterns around ##
        let parts: Vec<&str> = macro_text.split("##").collect();

        for window in parts.windows(2) {
            let left = window[0].trim();
            let right = window[1].trim();

            // Check if concatenation would form a UCN
            if self.could_form_ucn(left, right) {
                return true;
            }
        }

        false
    }

    fn could_form_ucn(&self, left: &str, right: &str) -> bool {
        // Check various patterns that could form UCNs when concatenated

        // Pattern 1: \u + digits
        if left.ends_with("\\u") && right.chars().all(|c| c.is_ascii_hexdigit()) && right.len() <= 4
        {
            return true;
        }

        // Pattern 2: \U + digits
        if left.ends_with("\\U") && right.chars().all(|c| c.is_ascii_hexdigit()) && right.len() <= 8
        {
            return true;
        }

        // Pattern 3: partial UCN + remaining digits (short form)
        if left.starts_with("\\u") && left.len() < 6 && right.chars().all(|c| c.is_ascii_hexdigit())
        {
            let total_len = left.len() - 2 + right.len(); // -2 for \u
            if total_len == 4 {
                return true;
            }
        }

        // Pattern 4: partial UCN + remaining digits (long form)
        if left.starts_with("\\U")
            && left.len() < 10
            && right.chars().all(|c| c.is_ascii_hexdigit())
        {
            let total_len = left.len() - 2 + right.len(); // -2 for \U
            if total_len == 8 {
                return true;
            }
        }

        // Don't use Pattern 4 (combined check) as it causes false positives
        // when both args are already complete UCNs
        false
    }

    #[allow(dead_code)]
    fn contains_ucn_pattern(&self, text: &str) -> bool {
        // Check if text contains UCN patterns using string operations
        // Look for \uXXXX or \UXXXXXXXX patterns
        let mut chars = text.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                if let Some(&next_ch) = chars.peek() {
                    if next_ch == 'u' {
                        chars.next(); // consume 'u'
                        let hex_count = chars
                            .by_ref()
                            .take(4)
                            .filter(|c| c.is_ascii_hexdigit())
                            .count();
                        if hex_count == 4 {
                            return true;
                        }
                    } else if next_ch == 'U' {
                        chars.next(); // consume 'U'
                        let hex_count = chars
                            .by_ref()
                            .take(8)
                            .filter(|c| c.is_ascii_hexdigit())
                            .count();
                        if hex_count == 8 {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn has_ucn_concatenation_pattern(&self, args: &[String], macro_name: &str) -> bool {
        // Check if macro arguments suggest UCN concatenation

        // Look for known dangerous macro patterns
        if macro_name.contains("assign")
            || macro_name.contains("concat")
            || macro_name.contains("join")
        {
            for arg in args {
                if self.looks_like_ucn_fragment(arg) {
                    return true;
                }
            }
        }

        // Check for patterns where multiple args might form UCNs
        if args.len() >= 2 {
            for i in 0..args.len() - 1 {
                if self.could_form_ucn(&args[i], &args[i + 1]) {
                    return true;
                }
            }
        }

        false
    }

    fn looks_like_ucn_fragment(&self, arg: &str) -> bool {
        let cleaned = arg.trim();

        // Check for partial UCN patterns
        cleaned.starts_with("\\u") && cleaned.len() < 6
            || cleaned.starts_with("\\U") && cleaned.len() < 10
            || cleaned.ends_with("\\u")
            || cleaned.ends_with("\\U")
            || (cleaned.chars().all(|c| c.is_ascii_hexdigit())
                && (cleaned.len() == 2 || cleaned.len() == 4))
    }

    fn get_macro_arguments(&self, node: &Node, source: &str) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(arguments) = node.child_by_field_name("arguments") {
            for i in 0..arguments.child_count() {
                if let Some(child) = arguments.child(i) {
                    if child.kind() != "," {
                        let arg_text = get_node_text(&child, source).to_string();
                        args.push(arg_text);
                    }
                }
            }
        }

        args
    }

    /// Scan source text for UCN fragment patterns in macro invocations
    fn check_source_for_ucn_fragments(&self, source: &str, violations: &mut Vec<RuleViolation>) {
        for (line_num, line) in source.lines().enumerate() {
            // Skip comment lines
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }

            // Check for UCN fragment patterns in macro calls
            if let Some(violation) = self.check_line_for_ucn_fragments(line, line_num + 1) {
                violations.push(violation);
            }
        }
    }

    /// Check a single line for UCN fragment patterns
    fn check_line_for_ucn_fragments(&self, line: &str, line_num: usize) -> Option<RuleViolation> {
        // Extract all potential macro calls from the line, handling nested parens
        let calls = self.extract_macro_calls(line);

        // C keywords to skip
        let keywords = [
            "if", "else", "while", "for", "do", "switch", "case", "return", "sizeof", "typeof",
            "alignof", "_Alignof", "_Generic",
        ];

        for (macro_name, args_str) in calls {
            // If this is a keyword, recursively check inside its args
            if keywords.contains(&macro_name.as_str()) {
                if let Some(v) = self.check_line_for_ucn_fragments(&args_str, line_num) {
                    return Some(v);
                }
                continue;
            }

            let args: Vec<&str> = args_str.split(',').map(|s| s.trim()).collect();

            if args.len() < 2 {
                continue;
            }

            // Check all pairs of adjacent arguments
            for i in 0..args.len() - 1 {
                let arg1 = args[i];
                let arg2 = args[i + 1];

                // Check for short UCN pattern: \uXX + YY where XX.len + YY.len == 4
                if let Some(msg) = self.check_ucn_pair(arg1, arg2, "u", 4) {
                    return Some(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: msg,
                        file_path: String::new(),
                        line: line_num,
                        column: 1,
                        suggestion: Some("Use complete universal character names instead of concatenating fragments".to_string()),
                        ..Default::default()
                    });
                }

                // Check for long UCN pattern: \UXX + YYYYYY where XX.len + YY.len == 8
                if let Some(msg) = self.check_ucn_pair(arg1, arg2, "U", 8) {
                    return Some(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: msg,
                        file_path: String::new(),
                        line: line_num,
                        column: 1,
                        suggestion: Some("Use complete universal character names instead of concatenating fragments".to_string()),
                        ..Default::default()
                    });
                }
            }

            // Check for three-part concatenation: \u + XX + YY
            if args.len() >= 3 {
                for i in 0..args.len() - 2 {
                    if let Some(msg) = self.check_three_part_ucn(&args[i..i + 3]) {
                        return Some(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::High,
                            message: msg,
                            file_path: String::new(),
                            line: line_num,
                            column: 1,
                            suggestion: Some("Use complete universal character names instead of concatenating fragments".to_string()),
                            ..Default::default()
                        });
                    }
                }
            }
        }

        None
    }

    /// Extract macro calls from a line, handling nested parentheses
    fn extract_macro_calls(&self, line: &str) -> Vec<(String, String)> {
        let mut results = Vec::new();
        let mut i = 0;
        let chars: Vec<char> = line.chars().collect();

        while i < chars.len() {
            // Look for identifier followed by (
            if chars[i].is_alphabetic() || chars[i] == '_' {
                let start = i;
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let name: String = chars[start..i].iter().collect();

                // Skip whitespace
                while i < chars.len() && chars[i].is_whitespace() {
                    i += 1;
                }

                // Check for opening paren
                if i < chars.len() && chars[i] == '(' {
                    i += 1; // skip '('
                    let args_start = i;
                    let mut depth = 1;

                    // Find matching closing paren
                    while i < chars.len() && depth > 0 {
                        if chars[i] == '(' {
                            depth += 1;
                        } else if chars[i] == ')' {
                            depth -= 1;
                        }
                        if depth > 0 {
                            i += 1;
                        }
                    }

                    if depth == 0 {
                        let args: String = chars[args_start..i].iter().collect();
                        results.push((name, args));
                    }
                    i += 1; // skip ')'
                }
            } else {
                i += 1;
            }
        }

        results
    }

    /// Check if two arguments could form a UCN when concatenated
    fn check_ucn_pair(
        &self,
        arg1: &str,
        arg2: &str,
        ucn_char: &str,
        total_digits: usize,
    ) -> Option<String> {
        let prefix = format!("\\{}", ucn_char);

        // arg1 should start with \u or \U and have fewer than total_digits hex digits
        if !arg1.starts_with(&prefix) {
            return None;
        }

        let hex_part1 = &arg1[prefix.len()..];

        // Check that hex_part1 is all hex digits but incomplete
        if hex_part1.is_empty() || hex_part1.len() >= total_digits {
            return None;
        }
        if !hex_part1.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }

        // arg2 should be hex digits that complete the UCN
        if !arg2.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }

        // Check if together they form exactly total_digits hex chars
        if hex_part1.len() + arg2.len() == total_digits {
            return Some(format!(
                "Macro invocation may create universal character name \\{}{}{} through concatenation",
                ucn_char, hex_part1, arg2
            ));
        }

        None
    }

    /// Check for three-part UCN concatenation (\u, XX, YY)
    fn check_three_part_ucn(&self, args: &[&str]) -> Option<String> {
        if args.len() != 3 {
            return None;
        }

        // Check for \u + XX + YY pattern (short UCN)
        if args[0] == "\\u" {
            let hex1 = args[1];
            let hex2 = args[2];
            if hex1.chars().all(|c| c.is_ascii_hexdigit())
                && hex2.chars().all(|c| c.is_ascii_hexdigit())
                && hex1.len() + hex2.len() == 4
            {
                return Some(format!(
                    "Macro invocation may create universal character name \\u{}{} through three-way concatenation",
                    hex1, hex2
                ));
            }
        }

        // Check for \U + XX + YYYYYY pattern (long UCN)
        if args[0] == "\\U" {
            let hex1 = args[1];
            let hex2 = args[2];
            if hex1.chars().all(|c| c.is_ascii_hexdigit())
                && hex2.chars().all(|c| c.is_ascii_hexdigit())
                && hex1.len() + hex2.len() == 8
            {
                return Some(format!(
                    "Macro invocation may create universal character name \\U{}{} through three-way concatenation",
                    hex1, hex2
                ));
            }
        }

        None
    }
}
