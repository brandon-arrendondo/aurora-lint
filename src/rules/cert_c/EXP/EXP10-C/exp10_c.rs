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
//! A call is a side effect unless it can be shown pure:
//!
//! - a libc function known to be pure (`strlen`, `abs`, ...);
//! - a project function-like macro whose expansion is a pure expression
//!   (`#define BIT(n) (1ul << (n))`, `#define TCB_PTR(r) ((tcb_t *)(r))`,
//!   every bitfield accessor and cast helper a kernel is written in). The
//!   expansion comes from `analyze::macro_expand`, so a macro that wraps an
//!   impure call (`#define READ(p) in8(p)`) stays impure and a macro whose
//!   body cannot even be parsed as an expression is treated as impure;
//! - a cast that tree-sitter mis-parsed as a call: `(u64)(x)` comes back as
//!   a call to `u64` (`ast_utils::misparsed_cast_type_name`, task 675). The
//!   name is accepted as a type when it is a known typedef, or when it is
//!   not a known function at all -- `(name)(x)` on a real function is the
//!   rare macro-suppression idiom `(free)(p)`, and a function-pointer
//!   variable is called as `fp(x)` or `(*fp)(x)`, not `(fp)(x)`.
//!   A macro parameter in that position (Lua's `#define cast(t, e) ((t)(e))`)
//!   is resolved from the argument actually passed at each invocation.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::analyze::macro_expand::{self, FunctionMacro};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{get_node_text, misparsed_cast_type_name};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
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

/// How a function-like macro's expansion classifies, cached per macro name.
#[derive(Clone, Debug)]
enum MacroPurity {
    /// The expansion is an expression with no side effects of its own.
    Pure,
    /// The expansion assigns, calls something impure, or is not an
    /// expression at all.
    Impure,
    /// Pure except for `(param)(...)` shapes, which are casts when the
    /// argument bound to `param` is a type and calls otherwise. Holds the
    /// indices of the parameters used that way.
    CastParams(Vec<usize>),
}

#[derive(Default)]
pub struct Exp10C {
    /// Function-like macro table: `ProjectContext::function_macros` with the
    /// file under scan's own `#define`s laid over it. The file's definitions
    /// are what the compiler sees in this translation unit, and the only
    /// table there is when a single file is scanned without `-d`.
    function_macros: RefCell<HashMap<String, FunctionMacro>>,
    /// Simple typedef aliases, for confirming a mis-parsed cast's type name.
    typedef_types: RefCell<HashMap<String, String>>,
    /// `typedef struct Tag Alias;` names, same purpose.
    struct_typedef_aliases: RefCell<HashMap<String, String>>,
    /// Every function the prescan saw defined or declared.
    known_functions: RefCell<HashSet<String>>,
    /// Per-macro-name purity verdicts, computed on first use.
    macro_purity: RefCell<HashMap<String, MacroPurity>>,
}

impl Exp10C {
    pub fn new() -> Self {
        Self::default()
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

    fn set_project_context(&self, context: &ProjectContext) {
        *self.function_macros.borrow_mut() = context.function_macros.clone();
        *self.typedef_types.borrow_mut() = context.typedef_types.clone();
        *self.struct_typedef_aliases.borrow_mut() = context.struct_typedef_aliases.clone();
        *self.known_functions.borrow_mut() = context.known_functions.clone();
        self.macro_purity.borrow_mut().clear();
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.function_macros
            .borrow_mut()
            .extend(macro_expand::collect_function_macros(node, source));
        self.macro_purity.borrow_mut().clear();

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

        // The call's own body runs after both the designator and the
        // arguments are evaluated, so it is on neither side of that pair.
        let unsequenced_pair = !designator_calls.is_empty() && !arg_calls.is_empty();
        let mut calls = designator_calls;
        calls.extend(arg_calls);
        if !self.call_is_pure(&node, source) {
            calls.push(node);
        }

        if unsequenced_pair {
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
        let Some(function) = call.child_by_field_name("function") else {
            return false;
        };
        // `(u64)(x)`: a cast tree-sitter could not tell from a call.
        if let Some(name) = misparsed_cast_type_name(call, source) {
            return self.is_type_name(name);
        }
        if function.kind() != "identifier" {
            // `s->fn(x)`, `(*fp)(x)`, `(*pf[i])(x)`: a call through a
            // pointer, whose target nothing here can see.
            return false;
        }
        let name = get_node_text(&function, source);
        if Self::is_pure_function(name) {
            return true;
        }
        match self.macro_purity(name) {
            Some(MacroPurity::Pure) => true,
            Some(MacroPurity::CastParams(indices)) => {
                let Some(args) = call.child_by_field_name("arguments") else {
                    return false;
                };
                let mut cursor = args.walk();
                let args: Vec<Node> = args.named_children(&mut cursor).collect();
                indices.iter().all(|&i| {
                    args.get(i)
                        .map(|a| self.is_type_name(get_node_text(a, source).trim()))
                        .unwrap_or(false)
                })
            }
            Some(MacroPurity::Impure) | None => false,
        }
    }

    /// Purity of a project function-like macro by name, from its expansion;
    /// `None` if `name` is not a known macro.
    fn macro_purity(&self, name: &str) -> Option<MacroPurity> {
        if let Some(p) = self.macro_purity.borrow().get(name) {
            return Some(p.clone());
        }
        let macros = self.function_macros.borrow();
        let m = macros.get(name)?;
        let verdict = self.classify_macro(&macros, name, m);
        self.macro_purity
            .borrow_mut()
            .insert(name.to_string(), verdict.clone());
        Some(verdict)
    }

    /// Expand `name` with its own parameter names as arguments (so nested
    /// macros resolve but the parameters stay visible), parse the result as
    /// an expression, and look for anything that could be a side effect.
    fn classify_macro(
        &self,
        table: &HashMap<String, FunctionMacro>,
        name: &str,
        m: &FunctionMacro,
    ) -> MacroPurity {
        let Some(expanded) = macro_expand::expand_invocation(table, name, &m.params) else {
            return MacroPurity::Impure;
        };
        let snippet = format!("int _sqc_exp10_expansion_ = ({expanded});");
        let mut parser = tree_sitter::Parser::new();
        if parser.set_language(&crate::parser::c_language()).is_err() {
            return MacroPurity::Impure;
        }
        let Some(tree) = parser.parse(&snippet, None) else {
            return MacroPurity::Impure;
        };
        let root = tree.root_node();
        if root.has_error() {
            // Statement-like bodies (`do { ... } while (0)`), token pasting,
            // anything that is not one expression.
            return MacroPurity::Impure;
        }
        let Some(value) = root
            .named_child(0)
            .and_then(|d| d.child_by_field_name("declarator"))
            .and_then(|d| d.child_by_field_name("value"))
        else {
            return MacroPurity::Impure;
        };

        let mut cast_params = Vec::new();
        for n in query::find_descendants(value, |_| true) {
            match n.kind() {
                "assignment_expression"
                | "update_expression"
                | "gnu_asm_expression"
                | "compound_statement" => return MacroPurity::Impure,
                "call_expression" => {
                    if let Some(type_name) = misparsed_cast_type_name(&n, &snippet) {
                        if let Some(i) = m.params.iter().position(|p| p == type_name) {
                            cast_params.push(i);
                            continue;
                        }
                        if self.is_type_name(type_name) {
                            continue;
                        }
                        return MacroPurity::Impure;
                    }
                    let callee = n
                        .child_by_field_name("function")
                        .filter(|f| f.kind() == "identifier")
                        .map(|f| get_node_text(&f, &snippet));
                    // After `expand_invocation`'s rescan the only calls left
                    // are real functions (or macros it could not expand);
                    // only the libc pure list vouches for those.
                    match callee {
                        Some(c) if Self::is_pure_function(c) => {}
                        _ => return MacroPurity::Impure,
                    }
                }
                _ => {}
            }
        }
        if cast_params.is_empty() {
            MacroPurity::Pure
        } else {
            cast_params.sort_unstable();
            cast_params.dedup();
            MacroPurity::CastParams(cast_params)
        }
    }

    /// Whether `text`, found where tree-sitter mis-parsed a cast as a call,
    /// names a type. Known typedefs and anything spelled like a type qualify;
    /// a bare identifier does unless the prescan knows it as a function.
    fn is_type_name(&self, text: &str) -> bool {
        let text = text.trim();
        if text.is_empty() {
            return false;
        }
        if self.typedef_types.borrow().contains_key(text)
            || self.struct_typedef_aliases.borrow().contains_key(text)
        {
            return true;
        }
        if text.contains('*')
            || text.starts_with("struct ")
            || text.starts_with("union ")
            || text.starts_with("enum ")
            || text.starts_with("const ")
            || text.starts_with("volatile ")
        {
            return true;
        }
        let first = text.split_whitespace().next().unwrap_or("");
        if matches!(
            first,
            "void"
                | "char"
                | "short"
                | "int"
                | "long"
                | "float"
                | "double"
                | "signed"
                | "unsigned"
                | "_Bool"
                | "bool"
                | "size_t"
                | "ssize_t"
                | "ptrdiff_t"
                | "intptr_t"
                | "uintptr_t"
                | "int8_t"
                | "int16_t"
                | "int32_t"
                | "int64_t"
                | "uint8_t"
                | "uint16_t"
                | "uint32_t"
                | "uint64_t"
        ) {
            return true;
        }
        text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !self.known_functions.borrow().contains(text)
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
