//! ENV33-C: Do not call system()
//!
//! The C Standard system() function executes a specified command by invoking
//! an implementation-defined command processor, such as a UNIX shell or CMD.EXE
//! in Microsoft Windows. The POSIX popen() and Windows _popen() functions also
//! invoke a command processor but create a pipe between the calling program and
//! the executed command.
//!
//! Use of the system() function can result in exploitable vulnerabilities, in
//! the worst case allowing execution of arbitrary system commands.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! void process_file(const char *filename) {
//!     char cmd[512];
//!     sprintf(cmd, "process %s", filename);
//!     system(cmd);  // Vulnerable to command injection
//! }
//!
//! FILE *f = popen("ls -la", "r");  // Also vulnerable
//! ```
//!
//! **Compliant:**
//! ```c
//! // Use safer alternatives like exec() family or implement functionality directly
//! void process_file(const char *filename) {
//!     pid_t pid = fork();
//!     if (pid == 0) {
//!         execl("/usr/bin/process", "process", filename, NULL);
//!         _exit(1);
//!     }
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Detect any calls to system(), popen(), or _popen()
//! - Also detects Windows exec/spawn variants (_execl, _spawnl, etc.)
//! - Resolves macro aliases (#define SYSTEM system) via project context
//! - These functions are inherently risky and should be avoided
//! - Suggest safer alternatives like exec() family functions

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg;
use crate::analyze::const_eval;
use crate::analyze::context::ProjectContext;
use crate::analyze::function_summary::FunctionSummary;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Env33C {
    project_aliases: RefCell<HashMap<String, String>>,
    current_aliases: RefCell<HashMap<String, String>>,
    function_summaries: RefCell<HashMap<String, FunctionSummary>>,
    /// Reverse call graph: callee_name → caller names.
    callers: RefCell<HashMap<String, HashSet<String>>>,
}

impl Env33C {
    pub fn new() -> Self {
        Self {
            project_aliases: RefCell::new(HashMap::new()),
            current_aliases: RefCell::new(HashMap::new()),
            function_summaries: RefCell::new(HashMap::new()),
            callers: RefCell::new(HashMap::new()),
        }
    }
}

impl Default for Env33C {
    fn default() -> Self {
        Self::new()
    }
}

impl CertRule for Env33C {
    fn rule_id(&self) -> &'static str {
        "ENV33-C"
    }

    fn description(&self) -> &'static str {
        "Do not call system()"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ENV33-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project_aliases.borrow_mut() = context.macro_aliases.clone();
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();

        let mut callers: HashMap<String, HashSet<String>> = HashMap::new();
        for (caller, callees) in &context.call_graph {
            for callee in callees {
                callers
                    .entry(callee.clone())
                    .or_default()
                    .insert(caller.clone());
            }
        }
        *self.callers.borrow_mut() = callers;
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        // Merge project-level aliases with per-file aliases
        let mut aliases = self.project_aliases.borrow().clone();
        aliases.extend(const_eval::collect_macro_aliases(node, source));
        *self.current_aliases.borrow_mut() = aliases;

        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

/// Functions that introduce external/untrusted input into a program.
/// If a containing function calls any of these, data passed to system()/popen()
/// may be tainted and the call should remain flagged.
const TAINTED_SOURCE_FUNCTIONS: &[&str] = &[
    // Network I/O
    "recv", "recvfrom", "recvmsg", // Console/file input
    "fgets", "gets", "gets_s", "scanf", "fscanf", "sscanf", "wscanf", "fwscanf", "fread", "fgetc",
    "fgetwc", "getchar", "getwchar", "getc", "getwc", "fgetws", // Environment
    "getenv", "_wgetenv", // POSIX
    "read", "pread",
];

impl Env33C {
    /// Resolve a function name through macro aliases.
    /// If `name` is a macro alias for a dangerous function, returns the target.
    fn resolve_name(&self, name: &str) -> String {
        let aliases = self.current_aliases.borrow();
        if let Some(target) = aliases.get(name) {
            target.clone()
        } else {
            name.to_string()
        }
    }

    /// Check nodes for dangerous function calls
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                let resolved = self.resolve_name(&func_name);

                if self.is_dangerous_function(&resolved) {
                    // Check if the call can be suppressed:
                    // 1. Direct string literal argument → safe (no injection possible)
                    // 2. Local variable in a function with no tainted input sources → safe
                    // 3. Function parameter → keep flagging (caller may pass tainted data)
                    if self.is_safe_command_call(&call, source) {
                        // Skip — command is built from constants with no external input
                    } else {
                        let suggestion = match resolved.as_str() {
                            "system" => "Use the exec() family of functions (execl, execv, etc.) instead, which provide better control and security",
                            "popen" | "_popen" => "Use pipe() and fork() with exec() family functions for better security",
                            _ => "Use safer alternatives like the exec() family of functions"
                        };

                        let display_name = if func_name != resolved {
                            format!("{} (macro for {})", func_name, resolved)
                        } else {
                            func_name.to_string()
                        };

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            message: format!(
                                "Call to '{}' is prohibited. This function invokes a command \
                                 processor which can lead to command injection vulnerabilities. \
                                 The function executes arbitrary shell commands and is inherently \
                                 dangerous when user input is involved.",
                                display_name
                            ),
                            severity: self.severity(),
                            line: call.start_position().row + 1,
                            column: call.start_position().column + 1,
                            file_path: String::new(),
                            suggestion: Some(suggestion.to_string()),
                            requires_manual_review: None,
                        });
                    }
                }
            }
        }
    }

    /// Check if a system()/popen() call is safe (no tainted input flows to the command).
    ///
    /// Returns true (safe, suppress) when the argument is a local variable in a
    /// function that has no tainted input sources AND no pointer/string parameters
    /// that could carry untrusted data from callers.
    ///
    /// Returns false (keep flagging) when:
    /// - The argument is a function parameter
    /// - The function has pointer/string parameters (data may flow through them)
    /// - The containing function reads external input (recv, fgets, getenv, etc.)
    /// - The argument is a string literal (still a violation: PATH/shell risks)
    fn is_safe_command_call(&self, call_node: &Node, source: &str) -> bool {
        // If the first argument is a direct string literal, always flag —
        // system("cmd") is still an ENV33-C violation (PATH/shell risks)
        if let Some(args) = call_node.child_by_field_name("arguments") {
            for i in 0..args.child_count() {
                if let Some(child) = args.child(i) {
                    let kind = child.kind();
                    if kind != "(" && kind != ")" && kind != "," {
                        // First real argument
                        if kind == "string_literal" {
                            return false; // Keep flagging string literal commands
                        }
                        break;
                    }
                }
            }
        }

        // Find the containing function
        let func_node = match Self::find_containing_function(call_node) {
            Some(f) => f,
            None => return false,
        };

        // Direct taint-source call in this scope (e.g. fgets, recv, getenv)
        // means whatever the command var holds could be externally controlled.
        if self.function_has_tainted_source(&func_node, source) {
            return false;
        }

        // Helper-sink pattern: the function takes a pointer/string param that
        // could carry untrusted data from callers. Defer to callers: suppress
        // only when every caller's prescan summary shows no taint source and
        // no transitive return-tainted path. Unknown callers stay flagging.
        if Self::has_pointer_parameters(&func_node, source) {
            return self.callers_are_all_clean(&func_node, source);
        }

        // No pointer params and no tainted sources → data is locally-constructed
        true
    }

    /// True when we can prove every transitive caller of `func_node`'s
    /// function is free of direct taint sources and transitively-tainted
    /// return values. False when caller info is missing at any level or any
    /// ancestor caller is tainted.
    ///
    /// The reverse call graph is walked BFS-style because Juliet's variants
    /// 52/53/54 route data through multi-level forwarding sinks where the
    /// immediate caller is a clean pass-through but a grand-caller reads
    /// from a taint source (e.g. recv).
    fn callers_are_all_clean(&self, func_node: &Node, source: &str) -> bool {
        let Some(name) = cfg::get_function_name(func_node, source) else {
            return false;
        };
        let callers = self.callers.borrow();
        let Some(root_callers) = callers.get(name) else {
            return false;
        };
        if root_callers.is_empty() {
            return false;
        }

        let summaries = self.function_summaries.borrow();
        let mut visited: HashSet<String> = HashSet::new();
        let mut stack: Vec<String> = root_callers.iter().cloned().collect();

        while let Some(current) = stack.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            match summaries.get(&current) {
                Some(s) if !s.has_env03_taint_source && !s.returns_tainted => {}
                _ => return false,
            }
            if let Some(next) = callers.get(&current) {
                for c in next {
                    if !visited.contains(c) {
                        stack.push(c.clone());
                    }
                }
            }
        }
        true
    }

    /// Walk up the AST to find the containing function_definition.
    fn find_containing_function<'a>(node: &Node<'a>) -> Option<Node<'a>> {
        let mut current = node.parent();
        while let Some(n) = current {
            if n.kind() == "function_definition" {
                return Some(n);
            }
            current = n.parent();
        }
        None
    }

    /// Check if a function_definition has any pointer or array parameters.
    /// Functions with pointer params may receive tainted data from callers.
    fn has_pointer_parameters(func_node: &Node, source: &str) -> bool {
        if let Some(declarator) = func_node.child_by_field_name("declarator") {
            Self::find_pointer_params_in_subtree(&declarator, source)
        } else {
            false
        }
    }

    fn find_pointer_params_in_subtree(node: &Node, source: &str) -> bool {
        let Some(param_list) =
            query::find_first_descendant(*node, |n| n.kind() == "parameter_list")
        else {
            return false;
        };

        for i in 0..param_list.child_count() {
            if let Some(param) = param_list.child(i) {
                if param.kind() == "parameter_declaration" {
                    let param_text = get_node_text(&param, source);
                    // Skip (void) parameter
                    if param_text.trim() == "void" {
                        continue;
                    }
                    // Check if parameter type contains pointer/array indicators
                    if param_text.contains('*') || param_text.contains('[') {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if a function body calls any tainted input source functions.
    fn function_has_tainted_source(&self, func_node: &Node, source: &str) -> bool {
        self.scan_for_tainted_calls(func_node, source)
    }

    fn scan_for_tainted_calls(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(function) = n.child_by_field_name("function") else {
                return false;
            };
            let name = get_node_text(&function, source);
            // Resolve through macro aliases (e.g., GETENV → getenv)
            let resolved = self.resolve_name(&name);
            if TAINTED_SOURCE_FUNCTIONS.contains(&resolved.as_str()) {
                return true;
            }
            // Also check the original name (in case alias resolution fails)
            TAINTED_SOURCE_FUNCTIONS.contains(&name)
        })
        .is_some()
    }

    /// Check if function is a dangerous command processor invocation
    fn is_dangerous_function(&self, name: &str) -> bool {
        matches!(
            name,
            "system"
                | "popen"
                | "_popen"
                | "_execl"
                | "_execle"
                | "_execlp"
                | "_execv"
                | "_execve"
                | "_execvp"
                | "_spawnl"
                | "_spawnle"
                | "_spawnlp"
                | "_spawnv"
                | "_spawnve"
                | "_spawnvp"
        )
    }
}
