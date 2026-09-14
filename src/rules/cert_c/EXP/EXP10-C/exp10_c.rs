//! EXP10-C: Do not depend on the order of evaluation of subexpressions or the order
//! in which side effects take place
//!
//! The order in which the operands of most operators are evaluated is
//! unspecified in C, and function calls are only *indeterminately* sequenced
//! with respect to each other. Two side-effecting calls that are operands of
//! the same operator therefore run in an order the program cannot rely on.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! int x = f(1) + f(2);  // Order of f(1) and f(2) is unspecified
//! ```
//!
//! **Compliant:**
//! ```c
//! int x = f(1);
//! x += f(2);  // Side effects are sequenced
//! ```
//!
//! ## What counts as unsequenced
//!
//! Two side-effecting calls are reported when their nearest common ancestor
//! in the expression tree is an operator that does not sequence its operands:
//!
//! - a `binary_expression` other than `&&` / `||` (those have a sequence
//!   point between the operands);
//! - a `subscript_expression` (array operand vs. index);
//! - a `call_expression`, between a call in the function-designator position
//!   and one in the argument list -- `(*pf[f1()])(f2())`, the CERT wiki's
//!   second non-compliant example.
//!
//! A call nested *inside* another call's argument list is always sequenced
//! before that call's body, so `f(g(x))` is never a pair: `g` and `f` are
//! unsequenced only with respect to a third call outside both. The previous
//! implementation counted every call in the operand subtree, which made
//! `outer(inner(x)) + 1` a finding -- the largest single false-positive driver
//! across every real-world project (aurora_lint task 1147: 388 of 389
//! adjudicated findings were FP).
//!
//! `,`, `?:` and assignment sequence or exclude their operands, so calls
//! under them combine into one group that is only unsequenced against calls
//! *outside* the operator: `(f(), g()) + h()` reports, `(f(), g())` alone
//! does not. `sizeof` operands are not evaluated at all.
//!
//! Two side-effecting calls that are both **arguments of the same call** are
//! deliberately not reported. Their order is unspecified too, but the shape
//! is `printf("%d %d", next(), next())` and every `foo(get_a(), get_b())`
//! in ordinary C; the rule targets operator operands and the
//! designator-vs-argument case, where the CERT examples live.
//!
//! ## What counts as side-effecting
//!
//! A call is a side effect unless its callee is a libc function known to be
//! pure (`strlen`, `abs`, ...). Calls through pointers are always counted.

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

/// Expression nesting deeper than this is not walked. Recursion here is
/// bounded by expression depth, not file size, and real expressions are a
/// few dozen levels at most; the cap only exists so that generated code with
/// a thousand-term operator chain cannot exhaust the stack.
const MAX_EXPR_DEPTH: usize = 256;

/// Node kinds that are part of an expression tree: the walk propagates the
/// side-effecting calls found under them up to the enclosing operator.
/// Anything not listed is a statement, declaration or preprocessor
/// boundary, which sequences everything on either side of it.
const EXPR_KINDS: &[&str] = &[
    "binary_expression",
    "unary_expression",
    "pointer_expression",
    "cast_expression",
    "field_expression",
    "update_expression",
    "conditional_expression",
    "comma_expression",
    "assignment_expression",
    "compound_literal_expression",
    "initializer_list",
    "initializer_pair",
    "generic_expression",
    "call_expression",
    "argument_list",
    "subscript_expression",
    "parenthesized_expression",
    "sizeof_expression",
    "alignof_expression",
    "offsetof_expression",
];

#[derive(Default)]
pub struct Exp10C;

impl Exp10C {
    pub fn new() -> Self {
        Self
    }
}

impl CertRule for Exp10C {
    fn rule_id(&self) -> &'static str {
        "EXP10-C"
    }

    fn description(&self) -> &'static str {
        "Do not depend on the order of evaluation of subexpressions or the order in which side effects take place"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "EXP10-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Expression roots: expression nodes whose parent is not one, i.e.
        // one per full expression (an `if` condition, an initializer, an
        // expression statement, each clause of a `for`). Found iteratively;
        // only the walk *within* an expression recurses.
        let roots = query::find_descendants(*node, |n| {
            EXPR_KINDS.contains(&n.kind())
                && !n
                    .parent()
                    .map(|p| EXPR_KINDS.contains(&p.kind()))
                    .unwrap_or(false)
        });
        for root in roots {
            let (_, reports) = self.collect(root, source, 0);
            violations.extend(reports);
        }
    }
}

impl Exp10C {
    /// Walk one expression subtree.
    ///
    /// Returns the side-effecting calls in `node` that are exposed to its
    /// siblings -- every impure call under it, since none of them is
    /// sequenced against anything outside `node` -- and the violations to
    /// report for it. A node whose operands are unsequenced and carry calls
    /// on more than one side reports once, with the total, and that report
    /// replaces any from its operands so a `(f() + g()) * (h() + k())`
    /// statement produces one finding rather than three.
    fn collect<'t>(
        &self,
        node: Node<'t>,
        source: &str,
        depth: usize,
    ) -> (Vec<Node<'t>>, Vec<RuleViolation>) {
        if depth > MAX_EXPR_DEPTH {
            return (Vec::new(), Vec::new());
        }
        match node.kind() {
            // Operands are not evaluated.
            "sizeof_expression" | "alignof_expression" | "offsetof_expression" => {
                (Vec::new(), Vec::new())
            }
            "binary_expression" => {
                let sequenced = node
                    .child_by_field_name("operator")
                    .map(|op| matches!(get_node_text(&op, source), "&&" | "||"))
                    .unwrap_or(false);
                let groups: Vec<Node<'t>> = ["left", "right"]
                    .iter()
                    .filter_map(|f| node.child_by_field_name(f))
                    .collect();
                let (calls, reports) = self.collect_groups(&groups, source, depth);
                if !sequenced && spans_groups(&groups, &calls) {
                    let report = self.violation(
                        &node,
                        format!(
                            "Expression contains {} function calls with potentially unsequenced side effects. \
                             Order of evaluation is unspecified.",
                            calls.len()
                        ),
                        "Separate function calls into distinct statements to ensure defined evaluation order",
                    );
                    return (calls, vec![report]);
                }
                (calls, reports)
            }
            "subscript_expression" => {
                let groups: Vec<Node<'t>> = ["argument", "index"]
                    .iter()
                    .filter_map(|f| node.child_by_field_name(f))
                    .collect();
                let (calls, reports) = self.collect_groups(&groups, source, depth);
                if spans_groups(&groups, &calls) {
                    let report = self.violation(
                        &node,
                        format!(
                            "Subscript expression with {} function calls. \
                             Order of evaluation is unspecified.",
                            calls.len()
                        ),
                        "Store intermediate results in temporary variables",
                    );
                    return (calls, vec![report]);
                }
                (calls, reports)
            }
            "call_expression" => self.collect_call(node, source, depth),
            kind if EXPR_KINDS.contains(&kind) => {
                // Every other expression kind sequences or excludes its
                // operands relative to each other; their calls are only
                // unsequenced against something outside.
                let mut cursor = node.walk();
                let children: Vec<Node<'t>> = node.named_children(&mut cursor).collect();
                self.collect_groups(&children, source, depth)
            }
            _ => {
                // Not an expression: an `ERROR` tree-sitter recovered into
                // the middle of one, a GNU statement expression's block, a
                // preprocessor conditional. Whatever is inside is sequenced
                // by statement boundaries the walk cannot see, so nothing is
                // exposed upward; the expressions inside have a
                // non-expression parent, so `scan` walks them as roots of
                // their own.
                (Vec::new(), Vec::new())
            }
        }
    }

    /// A call: the function designator and each argument are operands.
    /// The designator's calls are unsequenced against every argument's;
    /// argument-vs-argument pairs are deliberately not reported (see the
    /// module doc). The call itself joins the exposed set unless it is pure.
    fn collect_call<'t>(
        &self,
        node: Node<'t>,
        source: &str,
        depth: usize,
    ) -> (Vec<Node<'t>>, Vec<RuleViolation>) {
        let function = node.child_by_field_name("function");
        let arguments = node.child_by_field_name("arguments");

        let (designator_calls, mut reports) = match function {
            Some(f) => self.collect(f, source, depth + 1),
            None => (Vec::new(), Vec::new()),
        };
        let mut arg_calls = Vec::new();
        if let Some(args) = arguments {
            let mut cursor = args.walk();
            for arg in args.named_children(&mut cursor) {
                let (c, r) = self.collect(arg, source, depth + 1);
                arg_calls.extend(c);
                reports.extend(r);
            }
        }

        let mut calls = designator_calls;
        let designator_count = calls.len();
        calls.extend(arg_calls);
        if !self.call_is_pure(&node, source) {
            calls.push(node);
        }

        if designator_count > 0 && calls.len() > designator_count {
            let total = calls.len();
            return (
                calls,
                vec![self.violation(
                    &node,
                    format!(
                        "Function call with {} nested function calls. \
                         Order of evaluation is unspecified.",
                        total
                    ),
                    "Store function results in temporary variables before use",
                )],
            );
        }
        (calls, reports)
    }

    /// Collect over sibling operands, concatenating exposed calls and reports.
    fn collect_groups<'t>(
        &self,
        groups: &[Node<'t>],
        source: &str,
        depth: usize,
    ) -> (Vec<Node<'t>>, Vec<RuleViolation>) {
        let mut calls = Vec::new();
        let mut reports = Vec::new();
        for g in groups {
            let (c, r) = self.collect(*g, source, depth + 1);
            calls.extend(c);
            reports.extend(r);
        }
        (calls, reports)
    }

    fn violation(&self, node: &Node, message: String, suggestion: &str) -> RuleViolation {
        RuleViolation {
            rule_id: self.rule_id().to_string(),
            message,
            severity: self.severity(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            file_path: String::new(),
            suggestion: Some(suggestion.to_string()),
            requires_manual_review: None,
        }
    }

    // ------------------------------------------------------------------
    // Purity
    // ------------------------------------------------------------------

    /// Whether this call expression has no side effects of its own (its
    /// arguments are judged separately).
    fn call_is_pure(&self, call: &Node, source: &str) -> bool {
        call.child_by_field_name("function")
            .filter(|f| f.kind() == "identifier")
            .map(|f| Self::is_pure_function(get_node_text(&f, source)))
            .unwrap_or(false)
    }

    /// Check if a function is known to be pure (no side effects).
    /// Pure functions do not need sequencing — calling them in any order
    /// produces the same result without affecting shared state.
    fn is_pure_function(name: &str) -> bool {
        matches!(
            name,
            // Math functions (C standard)
            "abs" | "fabs" | "fabsf" | "fabsl" | "labs" | "llabs"
            | "sqrt" | "sqrtf" | "sqrtl"
            | "sin" | "sinf" | "sinl"
            | "cos" | "cosf" | "cosl"
            | "tan" | "tanf" | "tanl"
            | "asin" | "acos" | "atan" | "atan2"
            | "ceil" | "ceilf" | "ceill"
            | "floor" | "floorf" | "floorl"
            | "round" | "roundf" | "roundl"
            | "fmod" | "fmodf" | "fmodl"
            | "pow" | "powf" | "powl"
            | "exp" | "expf" | "expl"
            | "log" | "logf" | "logl"
            | "log2" | "log10"
            | "hypot" | "hypotf"
            | "cbrt" | "cbrtf"
            | "trunc" | "truncf" | "truncl"
            // String query functions (read-only)
            | "strlen" | "wcslen" | "strnlen"
            | "strcmp" | "strncmp" | "strcasecmp" | "strncasecmp"
            | "memcmp"
            | "strchr" | "strrchr" | "strstr"
            // Type testing
            | "isdigit" | "isalpha" | "isalnum" | "isspace" | "isupper" | "islower"
            | "isxdigit" | "isprint" | "ispunct" | "iscntrl"
            // Conversion (read-only)
            | "toupper" | "tolower"
            | "atoi" | "atol" | "atoll" | "atof"
            | "strtol" | "strtoul" | "strtoll" | "strtoull" | "strtod"
        )
    }
}

/// Whether the exposed calls come from more than one of `groups` -- the
/// condition for a pair of them being unsequenced. Membership is by byte
/// range: a call belongs to the group whose span contains it.
fn spans_groups(groups: &[Node], calls: &[Node]) -> bool {
    let mut populated = 0;
    for g in groups {
        let range = g.byte_range();
        if calls
            .iter()
            .any(|c| range.start <= c.start_byte() && c.end_byte() <= range.end)
        {
            populated += 1;
            if populated >= 2 {
                return true;
            }
        }
    }
    false
}
