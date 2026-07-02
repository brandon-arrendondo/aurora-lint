use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

/// MSC41-C: Never hard code sensitive information
///
/// Detects hard-coded sensitive data like passwords, API keys, and encryption keys
/// that should not be embedded directly in source code.
pub struct Msc41C;

impl Msc41C {
    pub fn new() -> Self {
        Self
    }

    /// Check if a function name suggests it deals with sensitive information.
    /// Uses word-boundary-aware matching to avoid false positives from substring
    /// collisions (e.g., "db" in "p2p_dbg", "key" in "monkey").
    fn is_sensitive_function(name: &str) -> bool {
        let name_lower = name.to_lowercase();

        // Exact substring match for long, unambiguous keywords
        let exact_keywords = [
            "password",
            "passwd",
            "credential",
            "secret",
            "encrypt",
            "decrypt",
            "cipher",
        ];
        if exact_keywords
            .iter()
            .any(|keyword| name_lower.contains(keyword))
        {
            return true;
        }

        // Word-boundary match for short/ambiguous keywords.
        // A "word boundary" means the keyword is preceded by '_' or is at the
        // start of the name. We only check the leading boundary — "authenticate"
        // should match "auth" but "p2p_dbg" should not match "db".
        let boundary_keywords = ["auth", "login", "logon", "pwd", "database"];
        for keyword in &boundary_keywords {
            if let Some(pos) = name_lower.find(keyword) {
                let before_ok = pos == 0 || name_lower.as_bytes()[pos - 1] == b'_';
                if before_ok {
                    return true;
                }
            }
        }

        // Strict word-boundary match (both sides) for very short/ambiguous keywords
        // that cause too many FPs with leading-only matching.
        let strict_keywords = ["key", "token"];
        for keyword in &strict_keywords {
            if let Some(pos) = name_lower.find(keyword) {
                let before_ok = pos == 0 || name_lower.as_bytes()[pos - 1] == b'_';
                let after = pos + keyword.len();
                let after_ok = after == name_lower.len() || name_lower.as_bytes()[after] == b'_';
                if before_ok && after_ok {
                    return true;
                }
            }
        }

        false
    }

    /// Check if a variable name suggests it stores sensitive information.
    /// Uses word-boundary matching for short keywords to avoid false positives
    /// (e.g., "key" in "monkey", "pass" in "bypass", "pin" in "pinned").
    fn is_sensitive_variable_name(name: &str) -> bool {
        let name_lower = name.to_lowercase();

        // Long, unambiguous patterns — substring match is safe
        let exact_patterns = [
            "password",
            "passwd",
            "secret",
            "credential",
            "apikey",
            "api_key",
        ];
        if exact_patterns
            .iter()
            .any(|pattern| name_lower.contains(pattern))
        {
            return true;
        }

        // Short/ambiguous patterns — require word boundary ('_' or start/end)
        let boundary_patterns = ["pwd", "pass", "key", "token", "auth", "pin", "salt"];
        for pattern in &boundary_patterns {
            if let Some(pos) = name_lower.find(pattern) {
                let before_ok = pos == 0 || name_lower.as_bytes()[pos - 1] == b'_';
                let after = pos + pattern.len();
                let after_ok = after == name_lower.len() || name_lower.as_bytes()[after] == b'_';
                if before_ok && after_ok {
                    return true;
                }
            }
        }

        false
    }

    /// Relaxed check for strings passed to sensitive functions.
    /// Skips format strings, single-char delimiters, debug labels (with colons/spaces),
    /// but flags plausible credentials.
    fn looks_like_sensitive_in_context(text: &str) -> bool {
        let content = text.trim_matches('"').trim_matches('\'');
        if content.is_empty() || content.len() < 3 {
            return false;
        }
        // Skip format strings
        if content.contains('%') {
            return false;
        }
        // Skip debug labels (contain ": " or " - " patterns)
        if content.contains(": ") || content.contains(" - ") {
            return false;
        }
        // Skip error messages (start with "Could not", "Failed to", "Error", "Cannot", "Invalid")
        let lower = content.to_lowercase();
        if lower.starts_with("could not")
            || lower.starts_with("failed")
            || lower.starts_with("error")
            || lower.starts_with("cannot")
            || lower.starts_with("invalid")
            || lower.starts_with("unable")
            || lower.starts_with("no ")
        {
            return false;
        }
        // Skip algorithm/protocol identifiers (all caps or all caps+digits, < 10 chars)
        if content.len() < 10
            && content
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-' || c == '_')
        {
            return false;
        }
        true
    }

    /// Check if a string literal looks like sensitive data
    fn looks_like_sensitive_data(text: &str) -> bool {
        // Remove quotes
        let content = text.trim_matches('"').trim_matches('\'');

        // Empty strings are not sensitive
        if content.is_empty() {
            return false;
        }

        // Very short strings (< 3 chars) are likely not passwords
        if content.len() < 3 {
            return false;
        }

        // Common non-sensitive strings to exclude
        let non_sensitive = [
            "test",
            "example",
            "localhost",
            "127.0.0.1",
            "utf-8",
            "utf8",
            "http",
            "https",
            "file",
            "path",
            "name",
            "user",
            "admin",
            "root",
            "guest",
            "public",
            "private",
            "default",
        ];

        let content_lower = content.to_lowercase();
        if non_sensitive
            .iter()
            .any(|s| content_lower.contains(s) && content.len() < 20)
        {
            return false;
        }

        // If it contains mix of letters, numbers, or special chars, might be sensitive
        let has_letters = content.chars().any(|c| c.is_alphabetic());
        let has_digits = content.chars().any(|c| c.is_numeric());
        let has_special = content
            .chars()
            .any(|c| !c.is_alphanumeric() && !c.is_whitespace());

        // Passwords/keys typically have mixed character types
        (has_special || has_digits) && has_letters || (has_digits && has_special)
    }

    /// Check call expressions for hard-coded sensitive data
    fn check_call_expression(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() != "call_expression" {
            return;
        }

        // Get function name
        let mut func_name = String::new();
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "identifier" {
                func_name = get_node_text(&child, source).to_string();
                break;
            }
        }

        if func_name.is_empty() || !Self::is_sensitive_function(&func_name) {
            return;
        }

        // Check arguments for string literals
        cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "argument_list" {
                let mut arg_cursor = child.walk();
                for arg in child.children(&mut arg_cursor) {
                    Self::check_node_for_string_literals(
                        &arg,
                        source,
                        violations,
                        Some(&func_name),
                    );
                }
            }
        }
    }

    /// Check for string literals in a node and its children
    fn check_node_for_string_literals(
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        context_func: Option<&str>,
    ) {
        for n in query::find_descendants_of_kind(*node, "string_literal") {
            let text = get_node_text(&n, source);

            // In sensitive function context, use a relaxed heuristic that skips
            // obvious non-sensitive strings (format strings, debug labels, delimiters)
            // but flags plausible credentials. Outside context, use strict heuristic.
            let should_flag = if context_func.is_some() {
                Self::looks_like_sensitive_in_context(text)
            } else {
                Self::looks_like_sensitive_data(text)
            };

            if should_flag {
                let context = if let Some(func) = context_func {
                    format!(" passed to `{}`", func)
                } else {
                    String::new()
                };

                violations.push(RuleViolation {
                    rule_id: "MSC41-C".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Hard-coded sensitive information detected{}. Sensitive data like passwords, keys, or tokens should not be embedded in source code. Code: {}",
                        context,
                        text.trim()
                    ),
                    file_path: String::new(),
                    line: n.start_position().row + 1,
                    column: n.start_position().column + 1,
                    suggestion: Some(
                        "Consider reading sensitive data from environment variables, configuration files, or user input at runtime.".to_string()
                    ),
                    requires_manual_review: None,
                });
            }
        }
    }

    /// Check variable declarations/initializations for hard-coded sensitive data
    fn check_declaration(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() != "declaration" && node.kind() != "init_declarator" {
            return;
        }

        // Get variable name and check if it suggests sensitive data
        let mut var_name = String::new();
        let mut has_string_init = false;
        let mut init_node: Option<Node> = None;

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "init_declarator" {
                let mut init_cursor = child.walk();
                for init_child in child.children(&mut init_cursor) {
                    if init_child.kind() == "pointer_declarator"
                        || init_child.kind() == "identifier"
                    {
                        // Extract variable name
                        let decl_text = get_node_text(&init_child, source);
                        var_name = decl_text
                            .trim_start_matches('*')
                            .trim()
                            .split(|c: char| !c.is_alphanumeric() && c != '_')
                            .next()
                            .unwrap_or("")
                            .to_string();
                    } else if init_child.kind() == "string_literal" {
                        has_string_init = true;
                        init_node = Some(init_child);
                    }
                }
            }
        }

        // If variable name suggests sensitive data and it's initialized with a string
        if !var_name.is_empty() && Self::is_sensitive_variable_name(&var_name) && has_string_init {
            if let Some(string_node) = init_node {
                let text = get_node_text(&string_node, source);
                violations.push(RuleViolation {
                    rule_id: "MSC41-C".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Variable `{}` appears to store sensitive information and is initialized with a hard-coded string literal. Sensitive data should not be embedded in source code. Code: {}",
                        var_name,
                        text.trim()
                    ),
                    file_path: String::new(),
                    line: string_node.start_position().row + 1,
                    column: string_node.start_position().column + 1,
                    suggestion: Some(
                        "Consider reading sensitive data from environment variables, configuration files, or user input at runtime.".to_string()
                    ),
                    requires_manual_review: None,
                });
            }
        }
    }

    /// Check #define macros for hard-coded sensitive values.
    /// Pattern: `#define PASSWORD "ABCD1234!"`
    fn check_preproc_def(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() != "preproc_def" {
            return;
        }

        // Get macro name
        let macro_name = node
            .child_by_field_name("name")
            .map(|n| get_node_text(&n, source).to_string())
            .unwrap_or_default();

        if macro_name.is_empty() || !Self::is_sensitive_variable_name(&macro_name) {
            return;
        }

        // Check if the value contains a string literal
        if let Some(value) = node.child_by_field_name("value") {
            let value_text = get_node_text(&value, source);
            // Check for string literal (starts with " or L")
            let trimmed = value_text.trim();
            if (trimmed.starts_with('"') && trimmed.ends_with('"'))
                || (trimmed.starts_with("L\"") && trimmed.ends_with('"'))
            {
                violations.push(RuleViolation {
                    rule_id: "MSC41-C".to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Macro '{}' contains hard-coded sensitive information: {}. \
                         Sensitive data should not be embedded in source code.",
                        macro_name, trimmed
                    ),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some(
                        "Read sensitive data from environment variables, configuration files, \
                         or user input at runtime."
                            .to_string(),
                    ),
                    requires_manual_review: None,
                });
            }
        }
    }

    /// Recursively check all nodes
    fn check_node(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |_| true) {
            Self::check_call_expression(&n, source, violations);
            Self::check_declaration(&n, source, violations);
            Self::check_preproc_def(&n, source, violations);
        }
    }
}

impl CertRule for Msc41C {
    fn rule_id(&self) -> &'static str {
        "MSC41-C"
    }

    fn description(&self) -> &'static str {
        "Never hard code sensitive information"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "MSC41-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        Self::check_node(node, source, &mut violations);
        violations
    }
}
