//! POS05-C: Limit access to files by creating a jail
//!
//! Programs running with elevated privileges that perform file operations based on
//! user-controlled input should use chroot jails to restrict filesystem access.
//! Without a chroot jail, attackers can manipulate file paths to access arbitrary
//! files (e.g., /etc/passwd) with the program's privileges.
//!
//! A proper chroot jail implementation requires:
//! 1. Calling chroot() to establish the jail
//! 2. Calling chdir("/") to enter the jail root
//! 3. Dropping superuser privileges permanently (setgid/setuid)
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! // Direct file operations with user input
//! FILE *fp = fopen(argv[1], "w");  // Attacker controls filename
//! strncpy(x, argv[2], array_max);
//! fwrite(x, sizeof(x[0]), sizeof(x)/sizeof(x[0]), fp);
//! ```
//!
//! **Compliant:**
//! ```c
//! // Set up chroot jail first
//! setuid(0);
//! chroot("chroot/jail");
//! chdir("/");
//! setgid(getgid());
//! setuid(getuid());
//!
//! // Now file operations are confined
//! FILE *fp = fopen(argv[1], "w");
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pos05C;

impl CertRule for Pos05C {
    fn rule_id(&self) -> &'static str {
        "POS05-C"
    }

    fn description(&self) -> &'static str {
        "Limit access to files by creating a jail"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "POS05-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check if the code has a chroot jail setup
        let has_chroot_setup = self.has_chroot_jail_setup(node, source);

        // If no chroot setup exists, check for file operations with user input
        if !has_chroot_setup {
            self.check_file_operations_without_jail(node, source, &mut violations);
        }

        violations
    }
}

impl Pos05C {
    /// Check if the code has a proper chroot jail setup
    /// Looks for: chroot() followed by chdir("/") and privilege dropping
    fn has_chroot_jail_setup(&self, node: &Node, source: &str) -> bool {
        let mut has_chroot = false;
        let mut has_chdir = false;
        let mut has_setuid = false;

        self.search_chroot_pattern(
            node,
            source,
            &mut has_chroot,
            &mut has_chdir,
            &mut has_setuid,
        );

        // All three must be present for proper jail setup
        has_chroot && has_chdir && has_setuid
    }

    fn search_chroot_pattern(
        &self,
        node: &Node,
        source: &str,
        has_chroot: &mut bool,
        has_chdir: &mut bool,
        has_setuid: &mut bool,
    ) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                match func_name {
                    "chroot" => *has_chroot = true,
                    "chdir" => {
                        // Check if it's chdir("/")
                        if let Some(arguments) = call.child_by_field_name("arguments") {
                            let args_text = get_node_text(&arguments, source);
                            if args_text.contains("\"/\"") {
                                *has_chdir = true;
                            }
                        }
                    }
                    "setuid" | "setgid" => *has_setuid = true,
                    _ => {}
                }
            }
        }
    }

    /// Check for file operations using user-controlled input without a jail
    fn check_file_operations_without_jail(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                // Check if this is a file operation function
                if self.is_file_operation(func_name) {
                    // Check if arguments contain user-controlled input (argv, user input, etc.)
                    if let Some(arguments) = call.child_by_field_name("arguments") {
                        if self.uses_user_input(&arguments, source) {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                message: format!(
                                    "File operation '{}' uses potentially user-controlled input \
                                     without a chroot jail. Programs running with elevated \
                                     privileges should establish a chroot jail (chroot + chdir + \
                                     setuid) before performing file operations with user input.",
                                    func_name
                                ),
                                severity: self.severity(),
                                line: call.start_position().row + 1,
                                column: call.start_position().column + 1,
                                file_path: String::new(),
                                suggestion: Some(
                                    "Create a chroot jail before file operations: \
                                     setuid(0); chroot(\"jail\"); chdir(\"/\"); \
                                     setgid(getgid()); setuid(getuid());"
                                        .to_string(),
                                ),
                                requires_manual_review: Some(true),
                            });
                        }
                    }
                }
            }
        }
    }

    /// Check if a function is a file operation function
    fn is_file_operation(&self, func_name: &str) -> bool {
        matches!(
            func_name,
            "fopen"
                | "open"
                | "creat"
                | "freopen"
                | "fopen_s"
                | "remove"
                | "rename"
                | "unlink"
                | "chmod"
                | "chown"
        )
    }

    /// Check if arguments contain user-controlled input
    fn uses_user_input(&self, arguments: &Node, source: &str) -> bool {
        let args_text = get_node_text(arguments, source);

        // Common patterns for user input
        // argv[] is the most common indicator
        args_text.contains("argv[")
            || args_text.contains("getenv")
            || args_text.contains("gets")
            || args_text.contains("fgets")
            || args_text.contains("scanf")
    }
}
