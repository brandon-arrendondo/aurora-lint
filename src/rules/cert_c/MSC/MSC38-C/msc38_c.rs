//! MSC38-C: Do not treat a predefined identifier as an object if it might only be implemented as a macro
//!
//! This rule addresses undefined behavior that occurs when attempting to suppress
//! macro definitions for specific predefined identifiers that the C Standard requires
//! to be implemented as macros.
//!
//! The C Standard identifies eight identifiers that must not have their macro
//! definitions suppressed:
//! - assert
//! - errno
//! - math_errhandling
//! - setjmp
//! - va_arg, va_copy, va_end, va_start
//!
//! ## Non-compliant examples:
//!
//! **Suppressing assert macro with parentheses:**
//! ```c
//! #include <assert.h>
//!
//! typedef void (*handler_type)(int);
//!
//! void func(int e) {
//!     execute_handler(&(assert), e < 0);  // Undefined behavior
//! }
//! ```
//!
//! **Using #undef on protected identifier:**
//! ```c
//! #include <assert.h>
//! #undef assert  // Undefined behavior
//! ```
//!
//! **Manual declaration of errno:**
//! ```c
//! extern int errno;  // Undefined behavior - should use #include <errno.h>
//! ```
//!
//! ## Compliant solutions:
//!
//! **Wrapper function instead of suppressing macro:**
//! ```c
//! #include <assert.h>
//!
//! static void assert_handler(int value) {
//!     assert(value);
//! }
//!
//! void func(int e) {
//!     execute_handler(&assert_handler, e < 0);
//! }
//! ```
//!
//! **Proper header inclusion:**
//! ```c
//! #include <errno.h>  // Correct way to use errno
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Msc38C;

impl Msc38C {
    pub fn new() -> Self {
        Self
    }

    /// Identifiers that must not have their macro definitions suppressed
    const PROTECTED_IDENTIFIERS: [&'static str; 8] = [
        "assert",
        "errno",
        "math_errhandling",
        "setjmp",
        "va_arg",
        "va_copy",
        "va_end",
        "va_start",
    ];

    /// Check if identifier is protected
    fn is_protected_identifier(&self, identifier: &str) -> bool {
        Self::PROTECTED_IDENTIFIERS.contains(&identifier)
    }

    /// Check for #undef of protected identifiers
    fn check_preproc_undef(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() == "preproc_undef" {
            // Get the identifier being undefined
            if let Some(name_node) = node.child_by_field_name("name") {
                let identifier = get_node_text(&name_node, source).trim();

                if self.is_protected_identifier(identifier) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: format!(
                            "Attempting to #undef protected identifier '{}'. This identifier must not have its macro definition suppressed as it may only be implemented as a macro.",
                            identifier
                        ),
                        file_path: String::new(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        suggestion: Some(
                            format!("Remove the #undef directive for '{}'. If you need to use the underlying function, create a wrapper function instead.", identifier)
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Check for parenthesized identifiers (e.g., &(assert)) that suppress macros
    fn check_parenthesized_identifier(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for pointer_expression with & operator containing a parenthesized_expression
        if node.kind() == "pointer_expression" {
            // Check if this is an address-of operator (&)
            if let Some(operator_node) = node.child(0) {
                if get_node_text(&operator_node, source).trim() == "&" {
                    // Check if the argument is a parenthesized_expression
                    if let Some(argument_node) = node.child_by_field_name("argument") {
                        if argument_node.kind() == "parenthesized_expression" {
                            // Extract the identifier inside the parentheses
                            for i in 0..argument_node.child_count() {
                                if let Some(child) = argument_node.child(i) {
                                    if child.kind() == "identifier" {
                                        let identifier = get_node_text(&child, source).trim();

                                        if self.is_protected_identifier(identifier) {
                                            violations.push(RuleViolation {
                                                rule_id: self.rule_id().to_string(),
                                                severity: self.severity(),
                                                message: format!(
                                                    "Using '&({})' suppresses the macro definition for protected identifier '{}'. This results in undefined behavior.",
                                                    identifier, identifier
                                                ),
                                                file_path: String::new(),
                                                line: node.start_position().row + 1,
                                                column: node.start_position().column + 1,
                                                suggestion: Some(
                                                    format!("Create a wrapper function that calls '{}' and take the address of the wrapper instead.", identifier)
                                                ),
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
        }
    }

    /// Check for manual declarations of protected identifiers (especially errno)
    fn check_manual_declaration(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check for variable declarations of protected identifiers
        if node.kind() == "declaration" {
            // Look for storage class specifier "extern" (common for errno)
            let has_extern = (0..node.child_count()).any(|i| {
                if let Some(child) = node.child(i) {
                    if child.kind() == "storage_class_specifier" {
                        return get_node_text(&child, source).trim() == "extern";
                    }
                }
                false
            });

            // Check declarator for protected identifier
            if let Some(declarator) = node.child_by_field_name("declarator") {
                let identifier = self.extract_identifier_from_declarator(&declarator, source);

                if let Some(ident) = identifier {
                    if self.is_protected_identifier(&ident) {
                        let message = if has_extern {
                            format!(
                                "Manual 'extern' declaration of protected identifier '{}'. This identifier should only be accessed through the appropriate standard header.",
                                ident
                            )
                        } else {
                            format!(
                                "Manual declaration of protected identifier '{}'. This identifier should only be accessed through the appropriate standard header.",
                                ident
                            )
                        };

                        let suggestion = match ident.as_str() {
                            "errno" => "Include <errno.h> instead of manually declaring errno.",
                            "assert" => "Include <assert.h> instead of manually declaring assert.",
                            "setjmp" => "Include <setjmp.h> instead of manually declaring setjmp.",
                            "math_errhandling" => "Include <math.h> instead of manually declaring math_errhandling.",
                            "va_arg" | "va_copy" | "va_end" | "va_start" => "Include <stdarg.h> instead of manually declaring variadic argument macros.",
                            _ => "Include the appropriate standard header instead of manually declaring this identifier.",
                        };

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            message,
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some(suggestion.to_string()),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// Extract identifier from declarator node
    fn extract_identifier_from_declarator(
        &self,
        declarator: &Node,
        source: &str,
    ) -> Option<String> {
        match declarator.kind() {
            "identifier" => Some(get_node_text(declarator, source).trim().to_string()),
            "pointer_declarator" | "array_declarator" | "function_declarator" => {
                // Recursively search for the identifier
                if let Some(decl_node) = declarator.child_by_field_name("declarator") {
                    return self.extract_identifier_from_declarator(&decl_node, source);
                }
                None
            }
            _ => {
                // Search children for identifier
                for i in 0..declarator.child_count() {
                    if let Some(child) = declarator.child(i) {
                        if child.kind() == "identifier" {
                            return Some(get_node_text(&child, source).trim().to_string());
                        }
                        if let Some(ident) = self.extract_identifier_from_declarator(&child, source)
                        {
                            return Some(ident);
                        }
                    }
                }
                None
            }
        }
    }
}

impl CertRule for Msc38C {
    fn rule_id(&self) -> &'static str {
        "MSC38-C"
    }

    fn description(&self) -> &'static str {
        "Do not treat a predefined identifier as an object if it might only be implemented as a macro"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "MSC38-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Msc38C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for various violation patterns
        for n in query::find_descendants(*node, |_| true) {
            self.check_preproc_undef(&n, source, violations);
            self.check_parenthesized_identifier(&n, source, violations);
            self.check_manual_declaration(&n, source, violations);
        }
    }
}
