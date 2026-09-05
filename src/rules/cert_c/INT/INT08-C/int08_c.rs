use super::super::{CertRule, RuleViolation};
use crate::analyze::const_eval::{self, MacroConstantMap, ValueRange, VarRangeMap};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::float_typing::{self, StructFieldTypes};
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Int08C;

impl CertRule for Int08C {
    fn rule_id(&self) -> &'static str {
        "INT08-C"
    }

    fn description(&self) -> &'static str {
        "Verify that all integer values are in range"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "INT08-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let macros = const_eval::collect_macro_constants(node, source);

        // Each function gets its own `variables` scope: a same-named
        // variable in a different function is a different object, and
        // `collect_declarations` doesn't even see parameter declarations
        // (only `declaration`-kind locals), so a stale entry from one
        // function (e.g. a narrow `char c`) could leak into an unrelated
        // same-named variable in another function (e.g. an `int c`
        // parameter) and misfire here (task 418). Scope both the
        // collection and the check per `function_definition`, mirroring
        // EXP39-C/STR32-C's per-function reset pattern.
        let functions = query::find_descendants_of_kind(*node, "function_definition");
        if functions.is_empty() {
            let mut variables: HashMap<String, (String, usize)> = HashMap::new();
            self.collect_declarations(node, source, &mut variables);
            let types = float_typing::collect_variable_types(node, source);
            self.check_arithmetic_expressions(
                node,
                source,
                &variables,
                &types,
                &macros,
                &mut violations,
            );
        } else {
            for func in functions {
                let mut variables: HashMap<String, (String, usize)> = HashMap::new();
                self.collect_declarations(&func, source, &mut variables);
                let types = float_typing::collect_variable_types(&func, source);
                self.check_arithmetic_expressions(
                    &func,
                    source,
                    &variables,
                    &types,
                    &macros,
                    &mut violations,
                );
            }
        }

        violations
    }
}

impl Int08C {
    /// Collect variable declarations and their types
    fn collect_declarations(
        &self,
        node: &Node,
        source: &str,
        variables: &mut HashMap<String, (String, usize)>,
    ) {
        for n in query::find_descendants_of_kind(*node, "declaration") {
            let decl_text = get_node_text(&n, source);

            // Extract type and variable name
            if let Some((var_type, var_name)) = self.parse_declaration(&decl_text) {
                variables.insert(var_name, (var_type, n.start_position().row + 1));
            }
        }
    }

    /// Parse declaration to extract type and variable name
    fn parse_declaration(&self, decl_text: &str) -> Option<(String, String)> {
        let parts: Vec<&str> = decl_text.split_whitespace().collect();

        if parts.len() >= 2 {
            // Handle types like "int x", "unsigned int x", "long x"
            if parts.len() >= 3 && (parts[0] == "unsigned" || parts[0] == "signed") {
                // "unsigned int x" or "signed int x"
                let var_type = format!("{} {}", parts[0], parts[1]);
                let var_name = parts[2]
                    .trim_end_matches(';')
                    .trim_end_matches(',')
                    .split('=')
                    .next()?
                    .trim()
                    .to_string();
                return Some((var_type, var_name));
            } else {
                // Simple type like "int x" or "long x"
                let var_type = parts[0].to_string();
                let var_name = parts[1]
                    .trim_end_matches(';')
                    .trim_end_matches(',')
                    .split('=')
                    .next()?
                    .trim()
                    .to_string();
                return Some((var_type, var_name));
            }
        }

        None
    }

    /// Check arithmetic expressions for overflow risks
    fn check_arithmetic_expressions(
        &self,
        node: &Node,
        source: &str,
        variables: &HashMap<String, (String, usize)>,
        types: &HashMap<String, String>,
        macros: &MacroConstantMap,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check if this is a binary expression (arithmetic)
        if node.kind() == "binary_expression" {
            if let Some(op) = node.child_by_field_name("operator") {
                let op_text = get_node_text(&op, source);

                // `/`, `%` and `>>` are excluded entirely: none of them can
                // grow a value's magnitude past whatever the dividend/shiftee
                // already was, so a narrow-typed operand promoted to `int`
                // can never make one of these exceed `int`'s range (task
                // 755) -- unlike `+`/`-`/`*`/`<<`, which can grow magnitude
                // and so are still worth checking below.
                if matches!(op_text.trim(), "+" | "-" | "*" | "<<") {
                    // Get the operands
                    if let (Some(left), Some(right)) = (
                        node.child_by_field_name("left"),
                        node.child_by_field_name("right"),
                    ) {
                        // Check if operands involve narrow integer types
                        let left_vars = self.extract_variables(&left, source);
                        let right_vars = self.extract_variables(&right, source);

                        let mut all_vars: HashSet<String> = HashSet::new();
                        all_vars.extend(left_vars);
                        all_vars.extend(right_vars);

                        let mut narrow_vars: Vec<(&String, &String)> = all_vars
                            .iter()
                            .filter_map(|var| {
                                variables.get(var).and_then(|(var_type, _)| {
                                    self.is_narrow_integer_type(var_type)
                                        .then_some((var, var_type))
                                })
                            })
                            .collect();
                        // `all_vars` is a HashSet, so its iteration order is
                        // reseeded per process. The message names
                        // `narrow_vars[0]`, which made two runs of the same
                        // binary on the same tree report a different variable
                        // for one expression (`min_c` vs `max_c` at
                        // curl/src/tool_urlglob.c:265). Sort so the pick is
                        // stable -- see the MSC04-C determinism task, whose
                        // SCC-path half is the same defect.
                        narrow_vars.sort_unstable_by(|a, b| a.0.cmp(b.0));

                        if narrow_vars.is_empty() {
                            // No narrow-typed operand at all -- not this
                            // rule's concern (plain `int`/`long` overflow is
                            // INT32-C's, see is_narrow_integer_type's doc).
                        } else if op_text.trim() == "+" || op_text.trim() == "-" {
                            // `+`/`-` of narrow (char/short) operands can
                            // never overflow a >=32-bit promoted `int`: even
                            // the widest narrow magnitude (unsigned short's
                            // 65535) summed or differenced with another
                            // narrow value tops out in the low hundred
                            // thousands, nowhere near INT_MAX. Provably safe
                            // by construction -- nothing to flag.
                        } else if self.promoted_arithmetic_overflows_int(
                            node, source, types, macros, variables,
                        ) {
                            // `*`/`<<` CAN overflow a narrow-typed operand's
                            // promoted range (e.g. `unsigned short * unsigned
                            // short` can exceed INT_MAX), so these are the
                            // only operators left that need an actual bound
                            // check -- and only a *proven* one fires.
                            let (var, var_type) = narrow_vars[0];
                            if !self.has_overflow_protection(node, var, var_type, source) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    message: format!(
                                        "Arithmetic '{}' can leave the range of the 'int' its operands promote to (operand '{}' is '{}')",
                                        get_node_text(node, source).split_whitespace().collect::<Vec<_>>().join(" "),
                                        var,
                                        var_type
                                    ),
                                    severity: self.severity(),
                                    line: node.start_position().row + 1,
                                    column: node.start_position().column + 1,
                                    file_path: String::new(),
                                    suggestion: Some(format!(
                                        "Compute in a wider type (e.g., 'long' instead of '{}') or bound the operands before the operation",
                                        var_type
                                    )),
                                    requires_manual_review: None,
                                });
                                // Only report once per expression
                                return;
                            }
                        }
                    }
                }
            }
        }

        // Recursively check children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.check_arithmetic_expressions(&child, source, variables, types, macros, violations);
        }
    }

    /// True only when interval arithmetic over the operands' promoted
    /// ranges *proves* that `expr` (a `*`/`<<` already known to involve a
    /// narrow-typed operand) can leave a 32-bit `int`. Seeds every
    /// narrow-typed variable in scope with its promoted-type range so
    /// `const_eval::try_evaluate_range` can walk the whole expression tree,
    /// handling nested parens, literals and `#define` constants along the
    /// way.
    ///
    /// Positive-only, deliberately. An operand whose range cannot be resolved
    /// -- a struct field, a subscript, a call result, an unrelated wide
    /// variable -- yields `false` rather than falling back to a guard-text
    /// heuristic. Whatever overflow risk such an expression carries is the
    /// *wide* operand's, and `int` overflow is INT32-C's concern, not this
    /// rule's (see `is_narrow_integer_type`'s doc). Falling back re-emitted
    /// the very inverted premise task 755 fixed, on every expression the
    /// range engine could not resolve -- in real code, most of them.
    fn promoted_arithmetic_overflows_int(
        &self,
        expr: &Node,
        source: &str,
        types: &HashMap<String, String>,
        macros: &MacroConstantMap,
        variables: &HashMap<String, (String, usize)>,
    ) -> bool {
        // Floating-point arithmetic is not integer overflow. `(float)x *
        // (1.0f/31)` reaches this check only because a narrow variable
        // appears somewhere in it; without the guard its fate would rest on
        // however `try_evaluate_range` happens to treat a float literal.
        if float_typing::expr_is_float(expr, source, types, &StructFieldTypes::new()) {
            return false;
        }

        let mut var_ranges: VarRangeMap = HashMap::new();
        for (name, (var_type, _)) in variables {
            if let Some(range) = self.promoted_range_for_type(var_type) {
                var_ranges.insert(name.clone(), range);
            }
        }

        const_eval::try_evaluate_range(expr, source, macros, &var_ranges)
            .is_some_and(|range| !range.fits_in_signed(32))
    }

    /// The value range a narrow integer type takes on after promotion to
    /// `int`. Delegates to [`const_eval::promoted_range_for_type`], shared
    /// with `INT32-C` since task 926 found the same inverted premise there.
    fn promoted_range_for_type(&self, type_name: &str) -> Option<ValueRange> {
        const_eval::promoted_range_for_type(type_name)
    }

    /// Extract variable names from an expression
    fn extract_variables(&self, node: &Node, source: &str) -> HashSet<String> {
        query::find_descendants_of_kind(*node, "identifier")
            .into_iter()
            .map(|n| get_node_text(&n, source).trim().to_string())
            .collect()
    }

    /// Check if a type is a narrow integer type (prone to overflow)
    /// Per CERT INT08-C, narrow types are those smaller than int:
    /// char, short, and their signed/unsigned variants.
    /// int itself is NOT narrow - overflow on int is covered by INT32-C.
    ///
    /// Recorded in this rule's TOML as `[references] related = ["INT32-C"]`
    /// (task 626, cross-rule overlap policy:
    /// docs/design/cross-rule-overlap.md). This is a `related` tag, not a
    /// validated `defers_to` exception -- task 625 found only 16
    /// ground-truth-labeled co-located lines for this pair (all agree-FP),
    /// far short of the "every labeled instance" subsumption bar. If `int`
    /// is ever added back to the narrow-type set, it is a detection-behavior
    /// change and needs delta-adjudication before any precision claim.
    fn is_narrow_integer_type(&self, type_name: &str) -> bool {
        matches!(
            type_name,
            "short" | "char" | "signed short" | "unsigned short" | "signed char" | "unsigned char"
        )
    }

    /// Check if there's appropriate overflow protection for this expression
    fn has_overflow_protection(
        &self,
        expr_node: &Node,
        var_name: &str,
        _var_type: &str,
        source: &str,
    ) -> bool {
        // Find the containing scope
        let mut current = expr_node.parent();
        let mut scope: Option<Node> = None;

        while let Some(node) = current {
            if matches!(
                node.kind(),
                "compound_statement" | "function_definition" | "translation_unit" | "if_statement"
            ) {
                scope = Some(node);
                break;
            }
            current = node.parent();
        }

        if let Some(scope_node) = scope {
            // Look for overflow checks BEFORE this expression
            // Proper checks would be like: if (i >= INT_MAX) or if (i < INT_MAX)
            // NOT checks that use the overflowing expression itself like: if (i + 1 <= i)
            return self.find_proper_overflow_check(
                &scope_node,
                expr_node.start_position().row,
                var_name,
                source,
            );
        }

        false
    }

    /// Find proper overflow check that comes BEFORE the expression
    fn find_proper_overflow_check(
        &self,
        scope: &Node,
        expr_line: usize,
        var_name: &str,
        source: &str,
    ) -> bool {
        query::find_descendants_of_kind(*scope, "if_statement")
            .into_iter()
            .filter(|n| n.start_position().row < expr_line)
            .any(|n| {
                let Some(condition) = n.child_by_field_name("condition") else {
                    return false;
                };
                let cond_text = get_node_text(&condition, source);

                // Check for proper overflow protection patterns
                // Good: "i >= INT_MAX", "i < INT_MAX", "i > MAX_VALUE"
                // Bad: "i + 1 <= i" (uses the overflowing expression itself)
                cond_text.contains(var_name) && self.is_proper_range_check(&cond_text, var_name)
            })
    }

    /// Check if a condition is a proper range check
    fn is_proper_range_check(&self, condition: &str, var_name: &str) -> bool {
        // Proper checks compare the variable against limits like INT_MAX, MAX_VALUE
        // Not proper: checks that use arithmetic on the variable itself

        // Look for comparisons with MAX/MIN constants
        if (condition.contains("MAX") || condition.contains("MIN")) && condition.contains(var_name)
        {
            // Check that the variable appears WITHOUT arithmetic operators applied to it
            // e.g., "i >= INT_MAX" is good, but "i + 1 <= i" is bad
            let has_var_arithmetic = condition.contains(&format!("{} +", var_name))
                || condition.contains(&format!("{} -", var_name))
                || condition.contains(&format!("{} *", var_name))
                || condition.contains(&format!("{} /", var_name))
                || condition.contains(&format!("+ {}", var_name))
                || condition.contains(&format!("- {}", var_name));

            return !has_var_arithmetic;
        }

        false
    }
}
