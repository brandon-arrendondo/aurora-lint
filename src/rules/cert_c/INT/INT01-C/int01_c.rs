//! INT01-C: Use size_t or rsize_t for all integer values representing the size of an object
//!
//! Variables that hold object sizes should be size_t, not int or other types,
//! to avoid overflow and ensure sufficient precision.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! void copy(size_t n) {
//!     int i;  // Wrong type for size
//!     for (i = 0; i < n; ++i) { ... }  // int compared with size_t
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! void copy(size_t n) {
//!     size_t i;  // Correct type
//!     for (i = 0; i < n; ++i) { ... }
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Int01C;

impl CertRule for Int01C {
    fn rule_id(&self) -> &'static str {
        "INT01-C"
    }

    fn description(&self) -> &'static str {
        "Use size_t or rsize_t for all integer values representing the size of an object"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "INT01-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Each function gets its own `size_t_vars`/`int_vars` scope: a
        // same-named variable in a different function is a different
        // object. Both maps were previously built by a single
        // whole-translation-unit walk, so a `size_t` parameter in one
        // function (e.g. `func_a(size_t len)`) could sit in `size_t_vars`
        // right alongside an unrelated same-named *plain* `int` local in a
        // different function (e.g. `func_b`'s `int len`), which
        // `find_int_size_t_comparisons` then reads as "an int compared
        // with size_t" for an ordinary int-to-int comparison in `func_b`
        // that never involves `func_a` at all (task 418; confirmed with a
        // minimal repro). Scope both maps and their two consuming checks
        // per `function_definition`, mirroring EXP39-C/STR32-C's
        // per-function reset pattern.
        let functions = query::find_descendants_of_kind(*node, "function_definition");
        let scopes: Vec<Node> = if functions.is_empty() {
            vec![*node]
        } else {
            functions
        };

        for scope in scopes {
            let mut size_t_vars: HashSet<String> = HashSet::new();
            let mut int_vars: HashMap<String, (usize, usize)> = HashMap::new();

            self.find_size_t_vars(&scope, source, &mut size_t_vars);
            self.find_int_vars(&scope, source, &mut int_vars);
            self.find_int_size_t_comparisons(
                &scope,
                source,
                &size_t_vars,
                &int_vars,
                &mut violations,
            );
            self.check_size_variable_usage(&scope, source, &size_t_vars, &mut violations);
        }

        // Parameter-name-based check is self-contained per parameter_list
        // and doesn't consume either cross-function map, so it can run
        // once over the whole translation unit as before.
        self.check_size_params(node, source, &mut violations);

        violations
    }
}

impl Int01C {
    /// Find size_t/rsize_t variables (parameters and declarations)
    fn find_size_t_vars(&self, node: &Node, source: &str, size_t_vars: &mut HashSet<String>) {
        for n in query::find_descendants_of_kinds(*node, &["parameter_declaration", "declaration"])
        {
            let decl_text = get_node_text(&n, source);
            // Check for size_t or rsize_t
            if decl_text.contains("size_t") || decl_text.contains("rsize_t") {
                let var_name = if n.kind() == "parameter_declaration" {
                    self.extract_param_name(&n, source)
                } else {
                    self.extract_var_name(&n, source)
                };
                if let Some(var_name) = var_name {
                    size_t_vars.insert(var_name);
                }
            }
        }
    }

    /// Find int variable declarations
    fn find_int_vars(
        &self,
        node: &Node,
        source: &str,
        int_vars: &mut HashMap<String, (usize, usize)>,
    ) {
        for n in query::find_descendants_of_kind(*node, "declaration") {
            let decl_text = get_node_text(&n, source);
            // Check for int but not unsigned int, not size_t, not uint*
            if decl_text.trim().starts_with("int ")
                || decl_text.contains(" int ")
                || decl_text.contains("\tint ")
            {
                if !decl_text.contains("unsigned")
                    && !decl_text.contains("size_t")
                    && !decl_text.contains("uint")
                {
                    if let Some(var_name) = self.extract_var_name(&n, source) {
                        int_vars.insert(
                            var_name,
                            (n.start_position().row + 1, n.start_position().column + 1),
                        );
                    }
                }
            }
        }
    }

    /// Find comparisons between int variables and size_t variables
    fn find_int_size_t_comparisons(
        &self,
        node: &Node,
        source: &str,
        size_t_vars: &HashSet<String>,
        int_vars: &HashMap<String, (usize, usize)>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kind(*node, "binary_expression") {
            if let Some(operator) = n.child_by_field_name("operator") {
                let op_text = get_node_text(&operator, source);
                // Check comparison operators
                if op_text == "<" || op_text == "<=" || op_text == ">" || op_text == ">=" {
                    if let (Some(left), Some(right)) = (
                        n.child_by_field_name("left"),
                        n.child_by_field_name("right"),
                    ) {
                        let left_text = get_node_text(&left, source);
                        let right_text = get_node_text(&right, source);

                        // Check if int var is compared with size_t var
                        if (int_vars.contains_key(left_text) && size_t_vars.contains(right_text))
                            || (int_vars.contains_key(right_text)
                                && size_t_vars.contains(left_text))
                        {
                            let int_var = if int_vars.contains_key(left_text) {
                                left_text
                            } else {
                                right_text
                            };
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                message: format!(
                                    "Variable '{}' of type int compared with size_t. \
                                     Use size_t for variables representing object sizes.",
                                    int_var
                                ),
                                severity: self.severity(),
                                line: n.start_position().row + 1,
                                column: n.start_position().column + 1,
                                file_path: String::new(),
                                suggestion: Some(format!(
                                    "Change declaration of '{}' from int to size_t",
                                    int_var
                                )),
                                requires_manual_review: None,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Extract parameter name
    fn extract_param_name(&self, param: &Node, source: &str) -> Option<String> {
        for i in 0..param.child_count() {
            if let Some(child) = param.child(i) {
                if child.kind() == "identifier" {
                    return Some(get_node_text(&child, source).to_string());
                }
            }
        }
        None
    }

    /// Extract variable name from declaration
    fn extract_var_name(&self, decl: &Node, source: &str) -> Option<String> {
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" || child.kind() == "identifier" {
                    return self.find_identifier(&child, source);
                }
            }
        }
        None
    }

    /// Find identifier in node
    fn find_identifier(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source).to_string());
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(name) = self.find_identifier(&child, source) {
                    return Some(name);
                }
            }
        }
        None
    }

    /// Check for function parameters representing sizes that don't use size_t
    fn check_size_params(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Every parameter_list in the C grammar is reachable only through a
        // function_declarator, so a flat kind-based search finds exactly the
        // same set of parameter lists the original nested/dominated recursive
        // walk did, just without the double-visit bookkeeping.
        for param_list in query::find_descendants_of_kind(*node, "parameter_list") {
            self.check_param_list(&param_list, source, violations);
        }
    }

    /// Check parameters in a parameter list for size-related names without size_t
    fn check_param_list(
        &self,
        param_list: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for i in 0..param_list.child_count() {
            if let Some(param) = param_list.child(i) {
                if param.kind() == "parameter_declaration" {
                    let param_text = get_node_text(&param, source);

                    // Skip if already using size_t or rsize_t
                    if param_text.contains("size_t") || param_text.contains("rsize_t") {
                        continue;
                    }

                    // Skip fixed-width integer types — on small/embedded targets (8/16-bit MCUs)
                    // uint8_t or uint16_t is the correct type for size parameters; size_t
                    // would waste scarce registers and uint8_t/uint16_t is intentional.
                    if param_text.contains("uint8_t")
                        || param_text.contains("uint16_t")
                        || param_text.contains("int8_t")
                        || param_text.contains("int16_t")
                    {
                        continue;
                    }

                    // Check for size-related parameter names
                    let size_names = [
                        "size",
                        "blocksize",
                        "len",
                        "length",
                        "count",
                        "bufsize",
                        "sz",
                    ];
                    let param_lower = param_text.to_lowercase();

                    for size_name in &size_names {
                        if param_lower.contains(size_name) {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                message: format!(
                                    "Parameter '{}' appears to represent a size but doesn't use size_t",
                                    param_text.trim()
                                ),
                                severity: self.severity(),
                                line: param.start_position().row + 1,
                                column: param.start_position().column + 1,
                                file_path: String::new(),
                                suggestion: Some("Use size_t for parameters representing object sizes".to_string()),
                                requires_manual_review: None,
                            });
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Check for variables used as sizes in malloc/alloc calls that aren't size_t
    fn check_size_variable_usage(
        &self,
        node: &Node,
        source: &str,
        size_t_vars: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for call expressions to allocation functions
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                // Check if this is an allocation function
                let alloc_funcs = ["malloc", "calloc", "realloc", "alloc", "aligned_alloc"];
                if alloc_funcs
                    .iter()
                    .any(|&f| func_name == f || func_name.ends_with("alloc"))
                {
                    // Check arguments for non-size_t size expressions
                    if let Some(args) = call.child_by_field_name("arguments") {
                        self.check_alloc_args(&args, source, size_t_vars, violations);
                    }
                }
            }
        }
    }

    /// Check allocation function arguments for non-size_t types
    fn check_alloc_args(
        &self,
        args: &Node,
        source: &str,
        size_t_vars: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // The size argument is typically the first (malloc) or second (calloc)
        // We flag variables that represent sizes but aren't size_t

        for i in 0..args.child_count() {
            if let Some(arg) = args.child(i) {
                // Skip parentheses, commas
                if arg.kind() == "(" || arg.kind() == ")" || arg.kind() == "," {
                    continue;
                }

                // sizeof() returns size_t by definition (C99 §6.5.3.4 ¶5) —
                // always the correct type, never flag it.
                if arg.kind() == "sizeof_expression" {
                    continue;
                }

                // sizeof(...) * N or N * sizeof(...) — the result is size_t
                if arg.kind() == "binary_expression" {
                    if let Some(op) = arg.child_by_field_name("operator") {
                        let op_text = get_node_text(&op, source);
                        if op_text == "*" {
                            let left = arg.child_by_field_name("left");
                            let right = arg.child_by_field_name("right");
                            let has_sizeof = left
                                .as_ref()
                                .is_some_and(|n| n.kind() == "sizeof_expression")
                                || right
                                    .as_ref()
                                    .is_some_and(|n| n.kind() == "sizeof_expression");
                            if has_sizeof {
                                continue;
                            }
                        }
                    }
                }

                // Check if the argument contains an identifier (variable)
                let arg_text = get_node_text(&arg, source);

                // Extract the base variable name from expressions like "length+1"
                let base_var = self.extract_base_var_name(&arg, source);

                // Skip if the base variable is already declared as size_t/rsize_t
                if let Some(ref var_name) = base_var {
                    if size_t_vars.contains(var_name) {
                        continue;
                    }
                }

                // If it's a variable name that looks like a size but isn't size_t
                // We detect this by checking if it's used in allocation context
                // and has a size-related name
                let size_related = ["length", "len", "size", "count", "sz", "n"]
                    .iter()
                    .any(|&name| arg_text.to_lowercase().contains(name));

                if size_related {
                    // This is a heuristic - the variable name suggests a size
                    // but we're using it in an allocation function
                    // The rule says all such values should be size_t
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        message: format!(
                            "Expression '{}' used as size argument to allocation function should use size_t type",
                            arg_text
                        ),
                        severity: self.severity(),
                        line: arg.start_position().row + 1,
                        column: arg.start_position().column + 1,
                        file_path: String::new(),
                        suggestion: Some("Ensure the variable used for size is declared as size_t".to_string()),
                        requires_manual_review: None,
                    });
                    return; // Only report once per call
                }
            }
        }
    }

    /// Extract the base variable name from an expression (e.g., "length+1" -> "length")
    fn extract_base_var_name(&self, node: &Node, source: &str) -> Option<String> {
        // If it's a simple identifier, return it
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source).to_string());
        }

        // If it's a binary expression, check the left side first
        if node.kind() == "binary_expression" {
            if let Some(left) = node.child_by_field_name("left") {
                return self.extract_base_var_name(&left, source);
            }
        }

        // Recurse into children to find an identifier
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(name) = self.extract_base_var_name(&child, source) {
                    return Some(name);
                }
            }
        }

        None
    }
}
