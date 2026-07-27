//! MSC12-C: Detect and remove code that has no effect or is never executed
//!
//! Detects several patterns of dead or no-effect code:
//! 1. Expression statements with no side effects (e.g., `a == b;`, `a + b;`, `5;`)
//! 2. Duplicate conditions in if/else-if chains
//! 3. Redundant sub-expressions in logical operators (`a == b && a == b`)
//! 4. Meaningless `continue` at end of loop body
//! 5. Empty control flow bodies (if/else/for/while with empty `{}`)
//! 6. Stray semicolons (`;` as a statement)
//! 7. Empty function bodies

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Msc12C;

impl Msc12C {
    pub fn new() -> Self {
        Self
    }

    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |_| true) {
            match n.kind() {
                "expression_statement" => {
                    self.check_no_effect_expression(&n, source, violations);
                }
                "if_statement" => {
                    self.check_duplicate_conditions(&n, source, violations);
                    self.check_empty_control_flow(&n, source, violations);
                }
                "for_statement" | "while_statement" | "do_statement" => {
                    self.check_meaningless_continue(&n, source, violations);
                    self.check_empty_control_flow(&n, source, violations);
                }
                "function_definition" => {
                    self.check_empty_function(&n, source, violations);
                }
                "compound_statement" => {
                    self.check_empty_standalone_block(&n, source, violations);
                }
                "switch_statement" => {
                    self.check_empty_switch_case(&n, source, violations);
                }
                "assignment_expression" => {
                    self.check_self_assignment(&n, source, violations);
                }
                _ => {}
            }

            // Check for redundant logical sub-expressions in various contexts
            if n.kind() == "binary_expression" {
                self.check_redundant_logical(&n, source, violations);
            }
        }
    }

    /// Check for expression statements that have no side effects.
    /// Patterns: `a == b;`, `a != b;`, `a + b;`, `5;`, `;`
    fn check_no_effect_expression(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get the expression child (skip the trailing `;`)
        let expr = match node.child(0) {
            Some(e) if e.kind() != ";" => e,
            _ => {
                // Stray semicolon: expression_statement with only ";"
                // Skip if inside a for statement (empty for(;;) components are valid)
                if let Some(parent) = node.parent() {
                    if parent.kind() == "for_statement" {
                        return;
                    }
                }
                // A MISSING `;` is a parser error-recovery placeholder, not
                // real source text (e.g. a labeled_statement inside an
                // #ifdef block whose body lives past the matching #endif —
                // tree-sitter has no preprocessor, so it can't see the body
                // and synthesizes a token to complete the grammar).
                if let Some(semi) = node.child(0) {
                    if semi.is_missing() {
                        return;
                    }
                }
                // A `;` immediately after an ERROR node that itself
                // contains a function_declarator is typically the tail of
                // a malformed declaration tree-sitter couldn't parse (e.g.
                // an attribute-style macro after a function prototype:
                // `void f(...) PRINTF_FORMAT(2, 3);` — the declaration +
                // macro call become an ERROR node and the real `;` is left
                // as an orphan sibling), not code a human wrote as a
                // standalone statement. Scoped to function_declarator
                // specifically (not any ERROR) so a genuinely no-effect
                // expression that also fails to parse at file scope
                // (`a == b;` outside a function) still gets flagged via
                // its own orphaned `;`.
                if let Some(prev) = node.prev_sibling() {
                    if prev.kind() == "ERROR"
                        && query::find_first_descendant(prev, |n| n.kind() == "function_declarator")
                            .is_some()
                    {
                        return;
                    }
                }
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: "Stray semicolon has no effect.".to_string(),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some("Remove the unnecessary semicolon".to_string()),
                    ..Default::default()
                });
                return;
            }
        };

        // Skip macro invocations — they may have side effects we can't see
        if expr.kind() == "call_expression" {
            return;
        }

        // Cast-to-void is intentional suppression: (void)x;
        if expr.kind() == "cast_expression" {
            let type_text = expr
                .child_by_field_name("type")
                .map(|t| get_node_text(&t, source))
                .unwrap_or_default();
            if type_text.trim() == "void" {
                return;
            }
        }

        // Comma expressions — last sub-expression determines effect
        if expr.kind() == "comma_expression" {
            return;
        }

        match expr.kind() {
            // Pure comparison used as a statement: a == b; a != b; a < b; etc.
            "binary_expression" => {
                if let Some(op_node) = expr.child_by_field_name("operator") {
                    let op = get_node_text(&op_node, source);
                    match op.trim() {
                        "==" | "!=" | "<" | ">" | "<=" | ">=" => {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: self.severity(),
                                message: format!(
                                    "Comparison '{}' used as a statement has no effect. \
                                     Did you mean '=' (assignment)?",
                                    op
                                ),
                                file_path: String::new(),
                                line: expr.start_position().row + 1,
                                column: expr.start_position().column + 1,
                                suggestion: Some(
                                    "Use '=' for assignment, or remove this statement".to_string(),
                                ),
                                ..Default::default()
                            });
                        }
                        // Arithmetic without assignment: a + b; a - b; a * b;
                        "+" | "-" | "*" | "/" | "%" => {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: self.severity(),
                                message: format!(
                                    "Arithmetic expression '{}' used as a statement has no effect. \
                                     The result is discarded.",
                                    get_node_text(&expr, source).trim()
                                ),
                                file_path: String::new(),
                                line: expr.start_position().row + 1,
                                column: expr.start_position().column + 1,
                                suggestion: Some(
                                    "Assign the result to a variable or remove this statement"
                                        .to_string(),
                                ),
                                ..Default::default()
                            });
                        }
                        // Bitwise/shift without assignment: x >> 3; x & mask;
                        ">>" | "<<" | "&" | "|" | "^" => {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: self.severity(),
                                message: format!(
                                    "Expression '{}' used as a statement has no effect. \
                                     The result is discarded.",
                                    get_node_text(&expr, source).trim()
                                ),
                                file_path: String::new(),
                                line: expr.start_position().row + 1,
                                column: expr.start_position().column + 1,
                                suggestion: Some(
                                    "Assign the result to a variable or remove this statement"
                                        .to_string(),
                                ),
                                ..Default::default()
                            });
                        }
                        _ => {}
                    }
                }
            }
            // Pointer dereference as statement with no assignment: *p++;
            // tree-sitter parses `*p++` as pointer_expression(update_expression)
            // The dereference result is discarded.
            "pointer_expression" => {
                // *p++ — the dereference is discarded, only p is incremented
                // But (*p)++ is an update_expression at the top level — that has effect
                let text = get_node_text(&expr, source);
                let trimmed = text.trim();
                if trimmed.starts_with('*') {
                    // Check if the inner expression is an update (p++) — dereference is wasted
                    if let Some(inner) = expr.child_by_field_name("argument") {
                        if inner.kind() == "update_expression" {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: self.severity(),
                                message: "Dereference of post-incremented pointer has no effect. \
                                     '*p++' dereferences then discards the value; \
                                     only the pointer is advanced."
                                    .to_string(),
                                file_path: String::new(),
                                line: expr.start_position().row + 1,
                                column: expr.start_position().column + 1,
                                suggestion: Some(
                                    "Use '(*p)++' to increment the pointed-to value, \
                                     or '++p' / 'p++' to just advance the pointer"
                                        .to_string(),
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
            // Bare literal as statement: `5;`, `"hello";`, `'c';`
            "number_literal" | "string_literal" | "char_literal" => {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!(
                        "Literal '{}' used as a statement has no effect.",
                        get_node_text(&expr, source).trim()
                    ),
                    file_path: String::new(),
                    line: expr.start_position().row + 1,
                    column: expr.start_position().column + 1,
                    suggestion: Some("Remove this statement or use its value".to_string()),
                    ..Default::default()
                });
            }
            // Bare identifier or field expression as statement: `x;` or `s.field;`
            "identifier" | "field_expression" => {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!(
                        "Expression '{}' used as a statement has no effect.",
                        get_node_text(&expr, source).trim()
                    ),
                    file_path: String::new(),
                    line: expr.start_position().row + 1,
                    column: expr.start_position().column + 1,
                    suggestion: Some("Remove this statement or use its value".to_string()),
                    ..Default::default()
                });
            }
            _ => {}
        }
    }

    /// Check for duplicate conditions in if/else-if chains.
    /// `if (x == 1) ... else if (x == 1) ...` — second branch is dead code.
    fn check_duplicate_conditions(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Collect all conditions in the if/else-if chain
        let mut conditions: Vec<(String, Node)> = Vec::new();

        let mut current = Some(*node);
        while let Some(if_node) = current {
            if if_node.kind() != "if_statement" {
                break;
            }
            if let Some(cond) = if_node.child_by_field_name("condition") {
                let cond_text = get_node_text(&cond, source);
                let trimmed = cond_text.trim().to_string();

                // Skip conditions with function calls — they may have side effects
                // (e.g., getc() advances the stream, so identical text != identical result)
                if self.contains_call(&cond) {
                    conditions.push((trimmed, cond));
                    current = if_node.child_by_field_name("alternative").and_then(|alt| {
                        if alt.kind() == "else_clause" {
                            (0..alt.child_count()).find_map(|i| {
                                let c = alt.child(i)?;
                                if c.kind() == "if_statement" {
                                    Some(c)
                                } else {
                                    None
                                }
                            })
                        } else if alt.kind() == "if_statement" {
                            Some(alt)
                        } else {
                            None
                        }
                    });
                    continue;
                }

                // Check for duplicate against earlier conditions
                for (prev_text, _) in &conditions {
                    if *prev_text == trimmed {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            message: format!(
                                "Duplicate condition '{}' in if/else-if chain. \
                                 The second branch is dead code.",
                                trimmed
                            ),
                            file_path: String::new(),
                            line: cond.start_position().row + 1,
                            column: cond.start_position().column + 1,
                            suggestion: Some(
                                "Check for the correct condition or remove the dead branch"
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                        break;
                    }
                }

                conditions.push((trimmed, cond));
            }

            // Follow else-if chain
            current = if_node.child_by_field_name("alternative").and_then(|alt| {
                if alt.kind() == "else_clause" {
                    // The if_statement inside the else clause
                    (0..alt.child_count()).find_map(|i| {
                        let c = alt.child(i)?;
                        if c.kind() == "if_statement" {
                            Some(c)
                        } else {
                            None
                        }
                    })
                } else if alt.kind() == "if_statement" {
                    Some(alt)
                } else {
                    None
                }
            });
        }
    }

    /// Check for redundant sub-expressions in logical operators.
    /// `a == b && a == b` — second operand is always the same as the first.
    fn check_redundant_logical(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() != "binary_expression" {
            return;
        }

        let op = match node.child_by_field_name("operator") {
            Some(o) => get_node_text(&o, source),
            None => return,
        };

        if op.trim() != "&&" && op.trim() != "||" {
            return;
        }

        let left = match node.child_by_field_name("left") {
            Some(l) => l,
            None => return,
        };
        let right = match node.child_by_field_name("right") {
            Some(r) => r,
            None => return,
        };

        let left_text = get_node_text(&left, source);
        let right_text = get_node_text(&right, source);

        if left_text.trim() == right_text.trim() {
            // Skip if the expression contains function calls (side effects)
            if self.contains_call(&left) {
                return;
            }

            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                message: format!(
                    "Redundant sub-expression in '{}' operator. \
                     Both sides are identical: '{}'.",
                    op.trim(),
                    left_text.trim()
                ),
                file_path: String::new(),
                line: right.start_position().row + 1,
                column: right.start_position().column + 1,
                suggestion: Some("Remove the duplicate sub-expression".to_string()),
                ..Default::default()
            });
        }
    }

    /// Check for meaningless `continue` at the end of a loop body.
    fn check_meaningless_continue(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let body = match node.child_by_field_name("body") {
            Some(b) if b.kind() == "compound_statement" => b,
            _ => return,
        };

        // Find the last non-brace statement
        let mut last_stmt = None;
        for i in 0..body.child_count() {
            if let Some(child) = body.child(i) {
                if child.kind() != "{" && child.kind() != "}" && child.kind() != "comment" {
                    last_stmt = Some(child);
                }
            }
        }

        if let Some(stmt) = last_stmt {
            if stmt.kind() == "continue_statement" {
                let _ = source; // already used above
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: "Unconditional 'continue' at end of loop body has no effect. \
                              The loop would continue anyway."
                        .to_string(),
                    file_path: String::new(),
                    line: stmt.start_position().row + 1,
                    column: stmt.start_position().column + 1,
                    suggestion: Some("Remove the unnecessary 'continue' statement".to_string()),
                    ..Default::default()
                });
            }
        }
    }

    /// Check for empty control flow bodies: if/else/for/while with empty `{}`
    fn check_empty_control_flow(
        &self,
        node: &Node,
        _source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        match node.kind() {
            "if_statement" => {
                // Check if the consequence (then-branch) is empty
                if let Some(consequence) = node.child_by_field_name("consequence") {
                    if self.is_empty_body(&consequence) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            message: "Empty if statement body has no effect.".to_string(),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some(
                                "Add code to the if body or remove the empty branch".to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
                // Check if the else clause has an empty body
                if let Some(alt) = node.child_by_field_name("alternative") {
                    if alt.kind() == "else_clause" {
                        // Find the body inside the else clause (skip "else" keyword)
                        for i in 0..alt.child_count() {
                            if let Some(child) = alt.child(i) {
                                if child.kind() == "compound_statement"
                                    && self.is_empty_body(&child)
                                {
                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        severity: self.severity(),
                                        message: "Empty else statement body has no effect."
                                            .to_string(),
                                        file_path: String::new(),
                                        line: alt.start_position().row + 1,
                                        column: alt.start_position().column + 1,
                                        suggestion: Some(
                                            "Add code to the else body or remove the empty branch"
                                                .to_string(),
                                        ),
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                }
            }
            "for_statement" | "while_statement" | "do_statement" => {
                if let Some(body) = node.child_by_field_name("body") {
                    if self.is_empty_body(&body) {
                        let kind = node.kind().replace("_statement", "");
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            message: format!("Empty {} loop body has no effect.", kind),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some(format!(
                                "Add code to the {} body or remove the empty loop",
                                kind
                            )),
                            ..Default::default()
                        });
                    }
                }
            }
            _ => {}
        }
    }

    /// Check for function definitions with empty bodies
    fn check_empty_function(
        &self,
        node: &Node,
        _source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(body) = node.child_by_field_name("body") {
            if self.is_empty_body(&body) {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: "Empty function body has no effect.".to_string(),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some("Add code to the function or remove it if unused".to_string()),
                    ..Default::default()
                });
            }
        }
    }

    /// Check for standalone empty blocks `{ }` inside function bodies
    fn check_empty_standalone_block(
        &self,
        node: &Node,
        _source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Only flag standalone blocks (parent is another compound_statement)
        // Skip function bodies, if/else/for/while/do bodies (handled elsewhere)
        if let Some(parent) = node.parent() {
            let pk = parent.kind();
            if pk != "compound_statement" && pk != "case_statement" && pk != "labeled_statement" {
                return;
            }
        } else {
            return;
        }

        if self.is_empty_body(node) {
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                message: "Empty code block has no effect.".to_string(),
                file_path: String::new(),
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                suggestion: Some("Add code to the block or remove it".to_string()),
                ..Default::default()
            });
        }
    }

    /// Check for switch cases that only contain `break` (no real code)
    fn check_empty_switch_case(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Find all case_statement children inside the switch body
        if let Some(body) = node.child_by_field_name("body") {
            // Collect indices of case_statement children (siblings in the
            // switch body) so we can tell whether a case falls straight
            // through into the next case/default label (grouped case
            // labels, e.g. `case 'D': case 'd': foo(); break;`) — that's a
            // standard idiom, not dead code, and each label's own
            // case_statement node has no children of its own to inspect.
            let case_indices: Vec<usize> = (0..body.child_count())
                .filter(|&i| {
                    body.child(i)
                        .map(|c| c.kind() == "case_statement")
                        .unwrap_or(false)
                })
                .collect();

            for (pos, &i) in case_indices.iter().enumerate() {
                let case_node = match body.child(i) {
                    Some(c) => c,
                    None => continue,
                };

                // Any statement/declaration in this case's own body, beyond
                // "case"/":"/the case value expression?
                let value_id = case_node.child_by_field_name("value").map(|v| v.id());
                let mut own_statement_count = 0usize;
                let mut has_real_code = false;
                for j in 0..case_node.child_count() {
                    if let Some(child) = case_node.child(j) {
                        let kind = child.kind();
                        if kind == "case" || kind == "default" || kind == ":" || kind == "comment" {
                            continue;
                        }
                        // Skip the case value expression itself (`case X:`
                        // has no body children before it; `default:` has no
                        // value at all, so this only ever matches the value).
                        if Some(child.id()) == value_id {
                            continue;
                        }
                        own_statement_count += 1;
                        if kind != "break_statement" {
                            has_real_code = true;
                        }
                    }
                }

                // tree-sitter-c's case_statement grammar doesn't accept a
                // leading preprocessor directive as a body child at all —
                // `case X:\n#ifdef Y\n  stmt;\n#endif\n  more;` parses with
                // the #ifdef block AND everything after it as SIBLINGS of
                // the case_statement in the switch body, not children of
                // it. Scan the sibling gap up to the next case/default (or
                // the end of the switch body) for such spillover.
                let next_i = case_indices
                    .get(pos + 1)
                    .copied()
                    .unwrap_or(body.child_count());
                let mut spillover_has_content = false;
                for k in (i + 1)..next_i {
                    if let Some(sib) = body.child(k) {
                        if !matches!(sib.kind(), "comment" | "}") {
                            spillover_has_content = true;
                            break;
                        }
                    }
                }
                if spillover_has_content {
                    has_real_code = true;
                }

                // A bare label with no statements at all (own body or
                // spillover), immediately followed by another case/default
                // label, is a grouped case label sharing the next label's
                // body — not empty.
                if own_statement_count == 0 && !spillover_has_content {
                    let falls_through_to_label = case_indices.get(pos + 1).is_some();
                    if falls_through_to_label {
                        continue;
                    }
                }

                if !has_real_code {
                    let _ = source;
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: "Empty case statement has no effect.".to_string(),
                        file_path: String::new(),
                        line: case_node.start_position().row + 1,
                        column: case_node.start_position().column + 1,
                        suggestion: Some("Add code to the case or remove it".to_string()),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Check for self-assignment: `x = x;`
    fn check_self_assignment(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let left = match node.child_by_field_name("left") {
            Some(l) => l,
            None => return,
        };
        let right = match node.child_by_field_name("right") {
            Some(r) => r,
            None => return,
        };

        // Only check plain `=` assignment, not compound (+=, etc.)
        if let Some(op) = node.child_by_field_name("operator") {
            if get_node_text(&op, source) != "=" {
                return;
            }
        }

        let left_text = get_node_text(&left, source);
        let right_text = get_node_text(&right, source);

        if left_text.trim() == right_text.trim() && !left_text.trim().is_empty() {
            // Skip if contains function calls (side effects in getter)
            if self.contains_call(&right) {
                return;
            }
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                message: format!("Self-assignment '{}' has no effect.", left_text.trim()),
                file_path: String::new(),
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                suggestion: Some(
                    "Remove the self-assignment or assign a different value".to_string(),
                ),
                ..Default::default()
            });
        }
    }

    /// Returns true if a compound_statement contains no meaningful statements
    fn is_empty_body(&self, node: &Node) -> bool {
        if node.kind() != "compound_statement" {
            return false;
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let kind = child.kind();
                if kind != "{" && kind != "}" && kind != "comment" {
                    return false;
                }
            }
        }
        true
    }

    /// Returns true if the node or any descendant is a call_expression.
    fn contains_call(&self, node: &Node) -> bool {
        query::find_first_descendant(*node, |n| n.kind() == "call_expression").is_some()
    }
}

impl CertRule for Msc12C {
    fn rule_id(&self) -> &'static str {
        "MSC12-C"
    }

    fn description(&self) -> &'static str {
        "Detect and remove code that has no effect or is never executed"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "MSC12-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}
