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
//! 8. A guard already excluded by the preceding early-return guard
//!    (`if(a||b||c) return; if(c) ...`) -- task 612

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{
    find_containing_function, get_node_text, is_defined_macro_name,
};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Msc12C {
    // Names of #define macros collected cross-file during pre-scan (same
    // mechanism DCL40-C uses, task 432): a bare object-like macro invoked
    // as a statement (`NODE_LOCK_SYS;`) commonly has its #define in a
    // different file (a header) than the .c file that invokes it.
    cross_file_macro_names: RefCell<HashSet<String>>,
}

impl Msc12C {
    pub fn new() -> Self {
        Self {
            cross_file_macro_names: RefCell::new(HashSet::new()),
        }
    }

    /// True if `name` is a known `#define` macro — either textually present
    /// in this same file's `source`, or collected cross-file during
    /// pre-scan. A parenthesis-less macro invoked as a bare identifier
    /// statement (`NODE_LOCK_SYS;`, `IPI_MEM_BARRIER;`) may expand to real
    /// code (lock acquire/release, a memory-barrier instruction) that
    /// tree-sitter can't see without preprocessing. See
    /// data/precision_audit/sel4/README.md (task 475).
    fn is_known_macro(&self, name: &str, source: &str) -> bool {
        is_defined_macro_name(name, source) || self.cross_file_macro_names.borrow().contains(name)
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
                    self.check_subsumed_guard(&n, source, violations);
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
        // A malformed declaration decorated by an unexpandable
        // attribute-style macro (e.g. `BOOT_BSS rootserver_mem_t
        // rootserver;`, seL4's section-placement macro) can leave
        // tree-sitter's error recovery splitting it into a `declaration`
        // with a synthesized MISSING ";" followed by the tail identifier
        // surfacing as its own orphan expression_statement — not code a
        // human wrote as a standalone statement. Same family as the
        // ERROR+function_declarator check further down (a different tree
        // shape: a variable declaration, not a function prototype).
        //
        // A `typedef` decorated the same way (`typedef T __attribute__((...))
        // name;`, e.g. seL4's `ulong_alias`) hits the identical error-recovery
        // split, but the preceding node is a `type_definition`, not a
        // `declaration` — a distinct tree-sitter-c node kind for typedefs.
        if let Some(prev) = node.prev_sibling() {
            if matches!(prev.kind(), "declaration" | "type_definition")
                && query::find_first_descendant(prev, |n| n.is_missing()).is_some()
            {
                return;
            }
        }

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
                // Deliberate busy-wait polling loop (`while (cond);`, or the
                // braced-with-a-lone-semicolon form `while (cond) { ; }`):
                // the condition itself does the real work (reads through a
                // pointer/field/subscript, or calls a function), so an
                // "empty" body is the idiom, not a bug. See
                // data/precision_audit/sel4/README.md (task 381/473) — this
                // was the dominant MSC12-C FP family on real embedded/kernel
                // code (UART/timer/IOMMU register polling).
                if let Some(cond) = self.enclosing_loop_condition_for_empty_body(node) {
                    if self.condition_indicates_polling(&cond) {
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
                // The unbraced form of the empty-then-branch-with-an-else
                // idiom (`if (cond)\n  ;\nelse if (...)`, pervasive in
                // curl's header-filtering chains). Same argument as
                // check_empty_control_flow: the `;` absorbs its condition
                // so the later arms don't run for it, and removing it
                // changes which branch executes.
                if let Some(parent) = node.parent() {
                    if parent.kind() == "if_statement"
                        && parent.child_by_field_name("consequence").map(|c| c.id())
                            == Some(node.id())
                        && parent.child_by_field_name("alternative").is_some()
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

        // ── Misparse guards (task 1004) ───────────────────────────────────
        // tree-sitter has no preprocessor and no type table, so several
        // non-expressions reach this point parsed as expression statements.
        // Every guard below rests on the same argument: what the parser
        // handed us is not what the programmer wrote, so "this statement has
        // no effect" is a claim about the parse, not about the code.

        // An expression statement is not valid C at file scope — a bare
        // `x;` outside any function does not compile. Reaching here means
        // error recovery split a declaration the parser could not resolve
        // and left its tail behind (`} sqlite3Prng;` after an
        // unexpandable `SQLITE_WSD` decorator, `LUA_API lua_State
        // *(lua_newthread)(...)` after an unknown-identifier blank).
        if node
            .parent()
            .is_some_and(|p| p.kind() == "translation_unit")
        {
            return;
        }

        // Residual parse debris inside the statement itself: an ERROR node
        // (a declaration decorated by an unexpandable attribute macro,
        // `BtShared *SQLITE_WSD list = 0;`) or a MISSING `;` (a condition
        // split across a #if/#else pair, so the parser synthesized a
        // terminator the source does not have). Same primitive the BOOT_BSS
        // and object-macro guards above use, applied to the statement's own
        // subtree rather than its predecessor.
        if query::find_first_descendant(*node, |n| n.is_error() || n.is_missing()).is_some() {
            return;
        }

        // An ERROR node immediately before the statement means the parser
        // lost the statement boundary and this "statement" starts mid-
        // construct: an inline-asm operand list (`: "memory"` after the
        // clobber colon) or JavaScript inside an emscripten `EM_ASM` block,
        // where the trailing `, 100);` of a JS call reads as C.
        if node.prev_sibling().is_some_and(|p| p.kind() == "ERROR") {
            return;
        }

        // A statement wrapped in a preprocessor conditional that the
        // preprocessor would have joined to its surroundings.
        if self.is_preproc_conditional_fragment(node, &expr, source) {
            return;
        }

        // Anything invoking a function may have side effects, so the
        // statement is not no-effect — whether the call is the whole
        // statement or one operand of it. This also covers the
        // declaration-vs-multiplication misparse, where a macro type
        // specifier reads as the left operand of a `*`
        // (`STACK_OF(X509) *sk;` → `STACK_OF(X509) * sk`): either it is a
        // declaration, or it is a real multiplication whose left operand
        // calls a function. Both mean "do not report".
        if self.contains_call(&expr) {
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
                // Mirrors the call_expression exception above, but for a
                // macro invoked without `()`. See is_known_macro's doc.
                if expr.kind() == "identifier"
                    && self.is_known_macro(&get_node_text(&expr, source), source)
                {
                    return;
                }
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

        // Parse debris, same argument as in check_no_effect_expression: a
        // `#if` line has no C parse, so tree-sitter recovers what it can and
        // the operands are whatever fell out. sqlite's
        // `#if defined(HAVE_POSIX_FALLOCATE) && HAVE_POSIX_FALLOCATE` leaves
        // the `)` as an ERROR sibling and both operands reading
        // `HAVE_POSIX_FALLOCATE` — identical only because the `defined(`
        // wrapper was dropped (task 1004).
        if query::find_first_descendant(*node, |n| n.is_error() || n.is_missing()).is_some() {
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

            // Textually identical is not the same as redundant: an operand
            // that increments or assigns evaluates to something different
            // each time, so the second occurrence is doing real work.
            // sqlite's varint decoder chains seven copies of
            // `(*pIter++)&0x80` precisely to walk the buffer (task 1004).
            if query::find_first_descendant(left, |n| {
                matches!(n.kind(), "update_expression" | "assignment_expression")
            })
            .is_some()
            {
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

    /// Check for a guard whose condition is already excluded by the
    /// immediately preceding guard, making its body unreachable.
    ///
    /// ```c
    /// if( a || b || c ) return 1;
    /// if( c ) return 1;        /* dead: reaching here means !c */
    /// ```
    ///
    /// This is the sequential-sibling analogue of `check_duplicate_conditions`,
    /// which only walks an if/else-if chain via `alternative` and therefore
    /// cannot see two `if`s that are plain statement siblings. It is also
    /// distinct from `check_redundant_logical`, which compares the two operands
    /// of a single `&&`/`||` node; here the repeated test appears once as a
    /// disjunct of the first condition and once as the whole second condition,
    /// so it is never the left/right pair of one binary_expression.
    ///
    /// Filed from a real instance found by hand in sqlite's
    /// `fts5TestUtf8()` (task 612), where the duplicated subcondition sits
    /// next to an off-by-one advance -- the copy-paste shape this looks for.
    ///
    /// Deliberately narrow, because "provably dead" has to actually hold:
    /// the two `if`s must be *immediately* consecutive (nothing in between
    /// can mutate the operands), the first must have no `else` and a body
    /// that unconditionally leaves the block, neither condition may contain a
    /// call, assignment or increment (a re-evaluation could differ), and no
    /// operand may be `volatile` (polling a hardware register re-reads by
    /// design).
    fn check_subsumed_guard(
        &self,
        compound: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let stmts: Vec<Node> = (0..compound.named_child_count())
            .filter_map(|i| compound.named_child(i))
            .filter(|c| c.kind() != "comment")
            .collect();

        for pair in stmts.windows(2) {
            let (first, second) = (pair[0], pair[1]);
            if first.kind() != "if_statement" || second.kind() != "if_statement" {
                continue;
            }
            // The first guard must be a bare `if (...) <jump>;` -- an else
            // branch means falling through does not imply the condition failed.
            if first.child_by_field_name("alternative").is_some() {
                continue;
            }
            if !Self::body_unconditionally_leaves(&first) {
                continue;
            }
            let (Some(c1), Some(c2)) = (
                first.child_by_field_name("condition"),
                second.child_by_field_name("condition"),
            ) else {
                continue;
            };
            if !Self::condition_is_reevaluation_safe(&c1)
                || !Self::condition_is_reevaluation_safe(&c2)
            {
                continue;
            }
            let c2_text = Self::normalize_condition(get_node_text(&c2, source));
            let disjuncts = Self::flatten_disjuncts(c1);
            // A single-disjunct first condition is the plain duplicate case;
            // require the repeated test to be one of several so this stays
            // the subsumption check and not a second reporter for it.
            if disjuncts.len() < 2 {
                continue;
            }
            if !disjuncts
                .iter()
                .any(|d| Self::normalize_condition(get_node_text(d, source)) == c2_text)
            {
                continue;
            }
            if Self::mentions_volatile_operand(&c2, source) {
                continue;
            }
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                message: format!(
                    "Condition '{}' was already excluded by the preceding guard \
                     on line {}, which returns when it holds. This branch is \
                     dead code.",
                    c2_text,
                    c1.start_position().row + 1
                ),
                file_path: String::new(),
                line: c2.start_position().row + 1,
                column: c2.start_position().column + 1,
                suggestion: Some(
                    "Remove the dead guard, or correct it if a different \
                     subscript or operand was intended"
                        .to_string(),
                ),
                ..Default::default()
            });
        }
    }

    /// True if `if_node`'s consequence always leaves the enclosing block, so
    /// execution continuing past it implies the condition was false.
    fn body_unconditionally_leaves(if_node: &Node) -> bool {
        let Some(body) = if_node.child_by_field_name("consequence") else {
            return false;
        };
        let terminal = |k: &str| {
            matches!(
                k,
                "return_statement" | "break_statement" | "continue_statement" | "goto_statement"
            )
        };
        if terminal(body.kind()) {
            return true;
        }
        if body.kind() != "compound_statement" {
            return false;
        }
        // A block leaves unconditionally only if its last statement does and
        // nothing before it can branch away from that conclusion; keep it to
        // the single-statement block, which is the shape that actually occurs.
        let inner: Vec<Node> = (0..body.named_child_count())
            .filter_map(|i| body.named_child(i))
            .filter(|c| c.kind() != "comment")
            .collect();
        inner.len() == 1 && terminal(inner[0].kind())
    }

    /// Flatten a `||` tree into its disjuncts, leaving any other expression
    /// as a single element.
    fn flatten_disjuncts<'a>(cond: Node<'a>) -> Vec<Node<'a>> {
        let inner = Self::strip_parens(cond);
        if inner.kind() == "binary_expression" {
            if let Some(op) = inner.child_by_field_name("operator") {
                if op.kind() == "||" {
                    if let (Some(l), Some(r)) = (
                        inner.child_by_field_name("left"),
                        inner.child_by_field_name("right"),
                    ) {
                        let mut out = Self::flatten_disjuncts(l);
                        out.extend(Self::flatten_disjuncts(r));
                        return out;
                    }
                }
            }
        }
        vec![inner]
    }

    fn strip_parens<'a>(node: Node<'a>) -> Node<'a> {
        let mut n = node;
        while n.kind() == "parenthesized_expression" {
            match (0..n.named_child_count())
                .filter_map(|i| n.named_child(i))
                .next()
            {
                Some(inner) => n = inner,
                None => break,
            }
        }
        n
    }

    /// Collapse whitespace and drop enclosing parentheses so the two spellings
    /// of one test compare equal.
    fn normalize_condition(text: &str) -> String {
        let mut t: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
        loop {
            let trimmed = t.trim();
            if trimmed.len() < 2 || !trimmed.starts_with('(') || !trimmed.ends_with(')') {
                break;
            }
            // Only strip when the leading '(' is the one the trailing ')' closes.
            let mut depth = 0i32;
            let mut matches_outer = true;
            for (i, ch) in trimmed.char_indices() {
                match ch {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 && i + 1 != trimmed.len() {
                            matches_outer = false;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if !matches_outer {
                break;
            }
            t = trimmed[1..trimmed.len() - 1].to_string();
        }
        t.trim().to_string()
    }

    /// True if evaluating this condition twice is guaranteed to give the same
    /// answer: no calls, no assignments, no increments/decrements.
    fn condition_is_reevaluation_safe(cond: &Node) -> bool {
        let impure = query::find_descendants(*cond, |n| {
            matches!(
                n.kind(),
                "call_expression" | "assignment_expression" | "update_expression"
            )
        });
        impure.is_empty()
    }

    /// True if any identifier in `cond` appears in a `volatile` declaration in
    /// the enclosing function -- a re-read of such an object may legitimately
    /// differ, so the second guard is not dead.
    ///
    /// Deliberately does not use `overflow_helpers::collect_variable_types`:
    /// that helper records only the type specifier (`primitive_type`,
    /// `sized_type_specifier`, `type_identifier`, `struct_specifier`) and drops
    /// the `type_qualifier` node, so `volatile int *reg` comes back as plain
    /// `int` and every volatile operand would slip through. Widening the shared
    /// helper to carry qualifiers would change what its other callers see, so
    /// the qualifier scan lives here.
    ///
    /// Any `volatile` anywhere in the declaration disqualifies the identifier;
    /// it does not try to tell `volatile int *p` (volatile pointee) from
    /// `int *volatile p` (volatile pointer), which errs toward not reporting.
    fn mentions_volatile_operand(cond: &Node, source: &str) -> bool {
        let Some(func) = find_containing_function(cond) else {
            return false;
        };
        let mut volatile_names: HashSet<&str> = HashSet::new();
        for decl in query::find_descendants(func, |n| {
            matches!(n.kind(), "declaration" | "parameter_declaration")
        }) {
            let qualified = (0..decl.child_count()).any(|i| {
                decl.child(i).is_some_and(|c| {
                    c.kind() == "type_qualifier" && get_node_text(&c, source).trim() == "volatile"
                })
            });
            if !qualified {
                continue;
            }
            for id in query::find_descendants_of_kind(decl, "identifier") {
                volatile_names.insert(&source[id.start_byte()..id.end_byte()]);
            }
        }
        if volatile_names.is_empty() {
            return false;
        }
        query::find_descendants_of_kind(*cond, "identifier")
            .iter()
            .any(|id| volatile_names.contains(&source[id.start_byte()..id.end_byte()]))
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
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        match node.kind() {
            "if_statement" => {
                // Check if the consequence (then-branch) is empty
                if let Some(consequence) = node.child_by_field_name("consequence") {
                    // An empty then-branch belonging to an if that has an
                    // `else` is NOT code with no effect: it absorbs its
                    // condition so the later arms don't run for it.
                    // `if (a) { } else if (b) { f(); }` is not equivalent to
                    // `if (b) { f(); }` -- delete the empty arm and f() now
                    // runs whenever a && b. That makes it deliberate case
                    // enumeration ("nothing to do in this case"), the
                    // dominant real-world shape of this finding (sqlite's
                    // `if(xDel==0){ /* noop */ }else if(...)`, hostap's
                    // config parsers, mosquitto's protocol dispatch).
                    //
                    // CERT's own noncompliant examples, and this rule's
                    // fail fixtures, are all STANDALONE ifs with no else --
                    // which stay flagged, because deleting one of those
                    // really does change nothing.
                    if node.child_by_field_name("alternative").is_none()
                        && self.is_empty_body(&consequence)
                        && !self.empty_body_has_verification_annotation(&consequence, source)
                    {
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
                                    && !self.empty_body_has_verification_annotation(&child, source)
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
                        // Same busy-wait polling exception as the bare-`;`
                        // form (see check_no_effect_expression): `while
                        // (cond) { }` with a condition that reads through
                        // indirection or a call is a deliberate spin-wait.
                        if let Some(cond) = node.child_by_field_name("condition") {
                            if self.condition_indicates_polling(&cond) {
                                return;
                            }
                        }
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
    fn check_empty_function(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(body) = node.child_by_field_name("body") {
            if self.is_empty_body(&body)
                && !self.empty_body_has_comment(&body)
                && !Self::is_static_inline(node, source)
            {
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

            // Two passes: the first records what each label contains, the
            // second decides what to report -- a case's removability
            // depends on whether the switch has a `default:` that would
            // catch its value, which is not knowable until every label has
            // been inspected.
            let mut cases: Vec<(Node, bool, bool)> = Vec::new();

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

                cases.push((case_node, value_id.is_none(), has_real_code));
            }

            // Does this switch have a `default:` that actually does
            // something? If so, no empty case in it is removable: delete
            // `case X: break;` and X stops matching a label, so it falls
            // to the default handler and the program behaves differently.
            // hostap's channel-width masking is the canonical shape --
            // `case WIDTH_160_80PLUS80: break;` next to `default: cap &=
            // ~WIDTH_MASK; break;` means "this width is fine, leave it
            // alone", and dropping the case silently masks the width out.
            let default_handles_the_rest = cases
                .iter()
                .any(|&(_, is_default, has_real_code)| is_default && has_real_code);

            for &(case_node, is_default, has_real_code) in &cases {
                if has_real_code {
                    continue;
                }
                // `default: break;` is not dead code either: MISRA C 2012
                // Rule 16.4 requires every switch to carry a default label,
                // and an empty one is the canonical way to say "every other
                // value is deliberately ignored". Removing it is a
                // standards regression, not a cleanup, and compilers ask
                // for it under -Wswitch-default.
                if is_default {
                    continue;
                }
                if default_handles_the_rest {
                    continue;
                }
                let _ = source;
                // What remains: a `case X: break;` in a switch with no
                // acting default. Deleting it really is behaviour-preserving,
                // and there is no structural signal separating a deliberate
                // no-op from a forgotten body -- `case cap_asid_control_cap:
                // break;` and an unfinished case look identical. Flag
                // rather than guess; see data/precision_audit/sel4/README.md
                // (task 474) for the measured ambiguity.
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: "Empty case statement has no effect.".to_string(),
                    file_path: String::new(),
                    line: case_node.start_position().row + 1,
                    column: case_node.start_position().column + 1,
                    suggestion: Some(
                        "Add code to the case, or remove it if the switch's default \
                         already handles this value"
                            .to_string(),
                    ),
                    requires_manual_review: Some(true),
                });
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

    /// True if this `function_definition` is declared `static inline`.
    ///
    /// An empty `static inline` function is a BUILD-CONFIGURATION SHIM, not
    /// dead code: it is the `#else` arm of a feature `#ifdef` in a header,
    /// defined so every call site compiles unchanged when the feature is
    /// off. Deleting it does not remove code that has no effect -- it
    /// breaks the build of every translation unit that calls it. hostap
    /// alone carries 226 of these (`static inline void
    /// wpas_nan_flush(struct wpa_supplicant *wpa_s) {}` and friends),
    /// which made "empty function body" the second-largest MSC12-C finding
    /// family on the real-world suite.
    ///
    /// `static inline` is the signal, not the file extension or the name:
    /// the rule sees only a syntax tree and a source buffer, and the
    /// storage class is what states the intent. A plain empty `static`
    /// function with no `inline` stays flagged -- nothing outside its own
    /// TU can call it, so it really may be dead.
    fn is_static_inline(node: &Node, source: &str) -> bool {
        let mut has_static = false;
        let mut has_inline = false;
        for i in 0..node.child_count() {
            let Some(child) = node.child(i) else { continue };
            if child.kind() != "storage_class_specifier" {
                continue;
            }
            match get_node_text(&child, source).trim() {
                "static" => has_static = true,
                "inline" | "__inline" | "__inline__" => has_inline = true,
                _ => {}
            }
        }
        has_static && has_inline
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

    /// Returns true if an (empty, per `is_empty_body`) compound_statement
    /// contains at least one comment — a deliberate "this is a documented
    /// no-op" idiom (`/* Don't need to do anything */`, `/* Do nothing */`)
    /// pervasive in real embedded/kernel platform-abstraction stub
    /// functions (see data/precision_audit/sel4/README.md, task 474).
    ///
    /// Deliberately scoped to `check_empty_function` ONLY — the same
    /// "lone comment in an otherwise-empty block" shape is also how CERT's
    /// own canonical MSC12-C wiki examples illustrate an empty if/else/for
    /// *branch* that should be flagged (`/* Handle error */`, `/* This
    /// code is unreachable */` in tests/fail/wiki_{,non}compliant_*.c), so
    /// applying this to check_empty_control_flow would suppress the
    /// rule's own textbook cases. A function body being fully empty is a
    /// different, much stronger signal (there is no "the rest of the
    /// function's logic is untouched" surrounding context the way a
    /// branch has) — real-world instances found here were all deliberate
    /// no-op stubs.
    fn empty_body_has_comment(&self, node: &Node) -> bool {
        if node.kind() != "compound_statement" {
            return false;
        }
        (0..node.child_count()).any(|i| {
            node.child(i)
                .map(|c| c.kind() == "comment")
                .unwrap_or(false)
        })
    }

    /// Returns true if an (empty, per `is_empty_body`) compound_statement
    /// contains a structured verification-annotation comment — the
    /// `/** TAG: "..." */` convention seL4's Isabelle/HOL proof toolchain
    /// uses to carry formal-verification hints inside otherwise-empty
    /// if/else branches (`/** AUXUPD: "(True, ptr_retyps ...)" */`,
    /// `/** GHOSTUPD: "(True, gs_new_frames ...)" */` —
    /// src/arch/x86/64/object/objecttype.c:191/209/233/239,
    /// src/arch/riscv/object/objecttype.c:205). These comments ARE the
    /// branch's entire purpose (consumed by a separate proof build,
    /// invisible to a plain C compile), unlike a generic explanatory
    /// comment.
    ///
    /// Deliberately narrower than `empty_body_has_comment`: matches only
    /// a doc-style `/**` (double-star) opener immediately followed by a
    /// known verification-tag + colon (see
    /// `is_verification_annotation_comment`), not any comment.
    /// `empty_body_has_comment` can't be reused here — task 474 found that
    /// a bare single-star
    /// comment inside an if/else/for branch is exactly the shape CERT's
    /// own MSC12-C wiki examples use to illustrate the violation
    /// (`/* Handle error */`, `/* This code is unreachable */` in
    /// tests/fail/wiki_{,non}compliant_*.c) — so treating any comment as
    /// exculpatory there would suppress the rule's own textbook cases.
    /// The structured tag+colon shape is a much stronger, more specific
    /// signal that doesn't collide with those fixtures.
    fn empty_body_has_verification_annotation(&self, node: &Node, source: &str) -> bool {
        if node.kind() != "compound_statement" {
            return false;
        }
        (0..node.child_count()).any(|i| {
            node.child(i)
                .filter(|c| c.kind() == "comment")
                .is_some_and(|c| {
                    Self::is_verification_annotation_comment(get_node_text(&c, source))
                })
        })
    }

    /// True if `text` (a single comment token's source text) opens with
    /// `/**` followed by one of `VERIFICATION_ANNOTATION_TAGS` and a
    /// colon. Deliberately an explicit tag allowlist rather than "any
    /// ALL_CAPS word + colon": that broader shape also matches ordinary
    /// `TODO:`/`FIXME:`/`NOTE:` markers, which are the opposite signal —
    /// a `TODO:`-only if/else branch is exactly the "author flagged this
    /// as unfinished" case MSC12-C should still catch. Extend the list if
    /// another codebase's proof-annotation convention turns up.
    fn is_verification_annotation_comment(text: &str) -> bool {
        const VERIFICATION_ANNOTATION_TAGS: &[&str] = &["AUXUPD", "GHOSTUPD"];
        let Some(rest) = text.strip_prefix("/**") else {
            return false;
        };
        let rest = rest.trim_start();
        VERIFICATION_ANNOTATION_TAGS.iter().any(|tag| {
            rest.strip_prefix(tag)
                .is_some_and(|after| after.starts_with(':'))
        })
    }

    /// True if `node` (an `expression_statement` with expression `expr`) is a
    /// fragment of a construct the preprocessor would have assembled, rather
    /// than a statement in its own right. Scans back from the statement to
    /// the nearest real code line *outside* the conditional structure that
    /// encloses it; something in between must be a conditional directive, or
    /// this is an ordinary statement and neither shape applies.
    ///
    /// 1. A bare identifier that the guarding directive itself names
    ///    (`#if defined(SQLITE_MEMORY_BARRIER)` around
    ///    `SQLITE_MEMORY_BARRIER;`). The guard is the codebase asserting the
    ///    name is a macro — the same fact [`Self::is_known_macro`] looks for
    ///    when the `#define` is reachable, which it is not when the macro
    ///    comes from a compiler flag or an external header.
    ///
    /// 2. That code line does not end a statement, so the guarded lines
    ///    continue it instead of starting a new one:
    ///    `identity->Flags = (unsigned long)`, then `#ifdef UNICODE`, then
    ///    `SEC_WINNT_AUTH_IDENTITY_UNICODE;`. The same shape splits `if(`
    ///    conditions across build configurations (pure-ftpd's
    ///    `# ifdef NON_ROOT_FTP` uid tests) and string-literal
    ///    concatenations (`"Bg:"` / `#ifndef` / `"h"` / `#endif` /
    ///    `"p:r:s:u:";`).
    ///
    /// The `depth` counter is what makes shape 2 work in an `#else` arm: the
    /// lines immediately above such a statement are the *sibling* arm, not
    /// its predecessor, so they have to be skipped along with anything in a
    /// nested conditional. Stopping at the first line seen would read the
    /// `#if` arm's last statement as the context and conclude, wrongly, that
    /// the `#else` arm starts fresh.
    ///
    /// Textual rather than structural because tree-sitter models a
    /// conditional inconsistently here: the `#else` that splits curl's
    /// ternary is a bare `preproc_call` sibling, while the one that splits
    /// pure-ftpd's option string is nothing at all — the statement's parent
    /// is the file's own header guard, hundreds of lines up. Scanning
    /// backwards from the statement is also bounded by how far the nearest
    /// enclosing-scope code line is, not by file size or nesting depth.
    fn is_preproc_conditional_fragment(&self, node: &Node, expr: &Node, source: &str) -> bool {
        let ident = (expr.kind() == "identifier")
            .then(|| get_node_text(expr, source).trim())
            .filter(|n| !n.is_empty());

        let line_start = source[..node.start_byte()].rfind('\n').map_or(0, |i| i + 1);
        let mut crossed_conditional = false;
        // Conditional blocks entered while walking up whose contents are a
        // sibling arm or a nested guard, and so are not this statement's
        // context.
        let mut depth = 0usize;

        for raw in source[..line_start].rsplit('\n') {
            let line = strip_trailing_comment(raw);
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with("//")
                || trimmed.starts_with("/*")
                || trimmed.starts_with('*')
            {
                continue;
            }
            if trimmed.starts_with('#') {
                match conditional_directive_kind(trimmed) {
                    Some(ConditionalDirective::Endif) => {
                        crossed_conditional = true;
                        depth += 1;
                    }
                    Some(ConditionalDirective::Else) => {
                        crossed_conditional = true;
                        // A later arm: everything back to the matching `#if`
                        // is the earlier arm's body, not our context.
                        depth += 1;
                    }
                    Some(ConditionalDirective::If) => {
                        crossed_conditional = true;
                        if depth > 0 {
                            depth -= 1;
                        } else if let Some(name) = ident {
                            // Shape 1, against the guard that decides
                            // whether this statement is compiled at all.
                            if trimmed.split(is_not_ident_char).any(|tok| tok == name) {
                                return true;
                            }
                        }
                    }
                    None => {}
                }
                continue;
            }
            if depth > 0 {
                continue;
            }
            // Shape 2: the first real code line in our own scope settles it.
            return crossed_conditional && !ends_a_statement(line);
        }
        false
    }

    /// Returns true if the node or any descendant is a call_expression.
    fn contains_call(&self, node: &Node) -> bool {
        query::find_first_descendant(*node, |n| n.kind() == "call_expression").is_some()
    }

    /// Given a stray-`;` `expression_statement`, find the condition of the
    /// enclosing while/do/for loop if this semicolon *is* that loop's body
    /// (`while (cond);`) or is the sole statement in a body block that
    /// otherwise only contains braces/comments (`while (cond) { ; }`).
    /// Returns None for a `;` anywhere else (e.g. a genuinely stray
    /// semicolon inside a real multi-statement block).
    fn enclosing_loop_condition_for_empty_body<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        let parent = node.parent()?;
        match parent.kind() {
            "while_statement" | "do_statement" | "for_statement" => {
                if parent.child_by_field_name("body").map(|b| b.id()) == Some(node.id()) {
                    parent.child_by_field_name("condition")
                } else {
                    None
                }
            }
            "compound_statement" => {
                let only_stmt = (0..parent.child_count()).all(|i| {
                    parent
                        .child(i)
                        .map(|c| matches!(c.kind(), "{" | "}" | "comment") || c.id() == node.id())
                        .unwrap_or(true)
                });
                if !only_stmt {
                    return None;
                }
                let grandparent = parent.parent()?;
                if matches!(
                    grandparent.kind(),
                    "while_statement" | "do_statement" | "for_statement"
                ) && grandparent.child_by_field_name("body").map(|b| b.id()) == Some(parent.id())
                {
                    grandparent.child_by_field_name("condition")
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// A loop condition "indicates polling" when it invokes a function
    /// (`while (vtd_read64(...) & 1);`), or reads through indirection
    /// (pointer dereference, `->`/`.` field access, array subscript)
    /// *combined with* an explicit comparison/bitwise/logical operator
    /// (`while (*UART_REG(STAT) & TXE);`, `while (timer->stat != DONE);`) —
    /// the hallmark of a hardware/shared-state busy-wait where the real
    /// work happens in the condition and an empty body is deliberate, not a
    /// bug. A *bare* dereference/field-read with no operator (`while
    /// (*flag);`, `while (!timer->stat);`) is deliberately NOT covered:
    /// structurally that's indistinguishable from a forgotten loop body
    /// (see tests/fail/testcases_empty_while_body.c), so it still gets
    /// flagged, same as a bare-variable/literal condition (`while (x);`).
    fn condition_indicates_polling(&self, cond: &Node) -> bool {
        if query::find_first_descendant(*cond, |n| n.kind() == "call_expression").is_some() {
            return true;
        }
        let has_operator =
            query::find_first_descendant(*cond, |n| n.kind() == "binary_expression").is_some();
        let has_indirection = query::find_first_descendant(*cond, |n| {
            matches!(
                n.kind(),
                "pointer_expression" | "field_expression" | "subscript_expression"
            )
        })
        .is_some();
        has_operator && has_indirection
    }
}

/// Splitter for identifier tokens: anything that cannot appear inside a C
/// identifier is a boundary, so `defined(NAME)` yields `defined` and `NAME`.
fn is_not_ident_char(c: char) -> bool {
    !c.is_alphanumeric() && c != '_'
}

/// The three roles a conditional-compilation directive plays when walking
/// *backwards* out of a block: `#endif` and `#else`/`#elif` mean a block was
/// entered, `#if`/`#ifdef`/`#ifndef` mean one was left.
enum ConditionalDirective {
    If,
    Else,
    Endif,
}

/// Classifies `line` (already trimmed, known to start with `#`), or None for
/// a directive that is not a build-configuration boundary — `#define`,
/// `#include`, `#pragma`.
fn conditional_directive_kind(line: &str) -> Option<ConditionalDirective> {
    let rest = line.trim_start_matches('#').trim_start();
    let word = rest
        .split(|c: char| is_not_ident_char(c))
        .next()
        .unwrap_or("");
    match word {
        "if" | "ifdef" | "ifndef" => Some(ConditionalDirective::If),
        "else" | "elif" => Some(ConditionalDirective::Else),
        "endif" => Some(ConditionalDirective::Endif),
        _ => None,
    }
}

/// Drop a trailing `// ...` or `/* ... */` comment so the terminator test
/// below looks at the code, not at what a comment happens to end with.
fn strip_trailing_comment(line: &str) -> &str {
    let line = match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    };
    match (line.rfind("/*"), line.rfind("*/")) {
        (Some(open), Some(close)) if close > open && line[close + 2..].trim().is_empty() => {
            &line[..open]
        }
        _ => line,
    }
}

/// True if `line` ends a statement or opens/closes a block, i.e. whatever
/// follows it starts fresh. A line ending in anything else (`=`, `|`, `(`,
/// `,`, `?`, a string literal) is mid-expression or mid-list, and code
/// guarded by a conditional right after it continues that expression.
///
/// `case X:` and `default:` end a statement position. A bare identifier plus
/// `:` reads as a goto label but is far more often the middle arm of a `?:`
/// spread over lines (`CURLSSLSET_OK :`), and a label immediately followed
/// by a conditional guarding a no-effect statement is not a shape real code
/// takes — so it is treated as a continuation.
fn ends_a_statement(line: &str) -> bool {
    let t = line.trim_end();
    if t.ends_with(';') || t.ends_with('{') || t.ends_with('}') {
        return true;
    }
    match t.strip_suffix(':') {
        Some(head) => {
            let head = head.trim();
            head.starts_with("case ") || head == "default"
        }
        None => false,
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

    fn set_project_context(&self, context: &ProjectContext) {
        *self.cross_file_macro_names.borrow_mut() = context.defined_macro_names.clone();
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}
