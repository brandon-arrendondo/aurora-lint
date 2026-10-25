// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

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
use crate::analyze::context::VisibleTypes;
use crate::analyze::noreturn::library_names_redefined_among;
use crate::manifest::Severity;
use crate::settings::{AnalysisSettings, IntFacts};
use crate::utility::cert_c::ast_utils::{self, get_node_text};
use crate::utility::cert_c::expr_type::{self, CType, Sign, TypeEnv};
use lang_parsing_substrate::query;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

#[derive(Default)]
pub struct Int01C {
    /// The typedefs and struct fields this file sees, so a parameter, a size
    /// argument or a compared operand is typed by its declaration (ADR-0006).
    visible: RefCell<VisibleTypes>,
    /// The integer data model the settings credit, for typing.
    data_model: Cell<IntFacts>,
}

/// The C library functions whose result is a `size_t`.
const SIZE_T_RESULTS: &[&str] = &[
    "strlen",
    "strnlen",
    "wcslen",
    "wcsnlen",
    "strspn",
    "strcspn",
    "strxfrm",
    "wcsxfrm",
    "strftime",
    "wcsftime",
    "mbstowcs",
    "wcstombs",
    "mbrlen",
    "mbrtowc",
    "wcrtomb",
    "mbsrtowcs",
    "wcsrtombs",
    "fread",
    "fwrite",
    "strlcpy",
    "strlcat",
];

/// What the checks type an expression or a declaration with.
struct Typing<'t, 'a> {
    env: &'t TypeEnv<'a>,
    visible: &'t VisibleTypes,
    /// The `SIZE_T_RESULTS` names this file defines as functions of its own.
    redefined: HashSet<String>,
}

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

    fn cert_id(&self) -> &'static str {
        "INT01-C"
    }

    fn set_visible_types(&self, types: &VisibleTypes) {
        *self.visible.borrow_mut() = types.clone();
    }

    fn set_analysis_settings(&self, settings: &std::sync::Arc<AnalysisSettings>) {
        self.data_model.set(settings.facts);
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let visible = self.visible.borrow();
        let env = TypeEnv::visible(&visible, self.data_model.get()).in_tree(*node);
        let typing = Typing {
            env: &env,
            visible: &visible,
            redefined: library_names_redefined_among(node, source, |n| SIZE_T_RESULTS.contains(&n)),
        };
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
        // that never involves `func_a` at all (confirmed with a
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
                &typing,
                &mut violations,
            );
            self.check_size_variable_usage(&scope, source, &size_t_vars, &typing, &mut violations);
        }

        // Parameter-name-based check is self-contained per parameter_list
        // and doesn't consume either cross-function map, so it can run
        // once over the whole translation unit as before.
        self.check_size_params(node, source, &typing, &mut violations);

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
        typing: &Typing,
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
                            let (int_var, int_node, size_node) = if int_vars.contains_key(left_text)
                            {
                                (left_text, left, right)
                            } else {
                                (right_text, right, left)
                            };
                            // The names only nominate the operands: each is
                            // typed by the declaration it resolves to here,
                            // so an int compared with an int, or a size_t
                            // with a size_t, of the same names elsewhere is
                            // not reported.
                            let int_signed = expr_type::expr_type(&int_node, source, typing.env)
                                .is_some_and(|t| t.is_unsigned() == Some(false));
                            if !int_signed || !is_size_t_typed(&size_node, source, typing) {
                                continue;
                            }
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
    fn check_size_params(
        &self,
        node: &Node,
        source: &str,
        typing: &Typing,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Every parameter_list in the C grammar is reachable only through a
        // function_declarator, so a flat kind-based search finds exactly the
        // same set of parameter lists the original nested/dominated recursive
        // walk did, just without the double-visit bookkeeping.
        for param_list in query::find_descendants_of_kind(*node, "parameter_list") {
            self.check_param_list(&param_list, source, typing, violations);
        }
    }

    /// Check parameters in a parameter list for size-related names without size_t
    fn check_param_list(
        &self,
        param_list: &Node,
        source: &str,
        typing: &Typing,
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
                    // Nor is one whose type is size_t through this file's
                    // typedefs (`lu_mem` for `typedef size_t lu_mem`).
                    if param
                        .child_by_field_name("type")
                        .is_some_and(|t| is_size_t_spelling(get_node_text(&t, source), typing))
                    {
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

                    // The parameter's own name nominates it, not its type's
                    // text (`key[MBEDTLS_DES_KEY_SIZE]`), and a size word
                    // counts only at the start or end of a word of the name
                    // (`len`, `nMaxCount`, `payloadlen`, `sizep`), not as
                    // letters inside another word (`silent`, `fileName`).
                    let Some((name, declarator)) = parameter_name(&param, source) else {
                        continue;
                    };
                    if !names_a_size(name) {
                        continue;
                    }
                    // Only an integer, or a pointer to or array of one, holds
                    // a size: a string, a struct or a function pointer named
                    // for one does not. A type out of reach is still reported.
                    let declared =
                        expr_type::declarator_type(&param, &declarator, source, typing.env);
                    if declared.is_some_and(|t| !may_hold_size(&t)) {
                        continue;
                    }
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
                        suggestion: Some(
                            "Use size_t for parameters representing object sizes".to_string(),
                        ),
                        requires_manual_review: None,
                    });
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
        typing: &Typing,
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
                        // `calloc(n, size)` and `aligned_alloc(align, size)`
                        // take two sizes, so a size_t first one does not end
                        // the scan.
                        let two_sizes =
                            func_name.ends_with("calloc") || func_name == "aligned_alloc";
                        self.check_alloc_args(
                            &args,
                            source,
                            size_t_vars,
                            typing,
                            two_sizes,
                            violations,
                        );
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
        typing: &Typing,
        two_sizes: bool,
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
                // always the correct type, never flag it. A bare one is the
                // element size of a `calloc`-style pair, so the count is
                // looked for after it.
                if arg.kind() == "sizeof_expression" {
                    continue;
                }

                // An argument that is not an integer (a handle, a pointer) is
                // not the size: the size is looked for among the arguments
                // after it.
                if expr_type::expr_type(&arg, source, typing.env)
                    .is_some_and(|t| !t.is_integer() && t != CType::Enum)
                {
                    continue;
                }

                // From here the argument is the size. One that is size_t
                // ends the scan: the arguments after it (a flag, an
                // alignment) are not sizes, and the size is of the right type.
                // An allocator that takes two sizes goes on to the second.

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
                                if two_sizes {
                                    continue;
                                }
                                return;
                            }
                        }
                    }
                }

                // A size_t global or member, or `strlen(s) + 1`.
                if is_size_t_typed(&arg, source, typing) {
                    if two_sizes {
                        continue;
                    }
                    return;
                }

                // Check if the argument contains an identifier (variable)
                let arg_text = get_node_text(&arg, source);

                // Extract the base variable name from expressions like "length+1"
                let base_var = self.extract_base_var_name(&arg, source);

                // Skip if the base variable is already declared as size_t/rsize_t.
                // The name may be declared size_t only in another block, so it
                // does not end the scan.
                if let Some(ref var_name) = base_var {
                    if size_t_vars.contains(var_name) {
                        continue;
                    }
                }

                // If it's a variable name that looks like a size but isn't size_t
                // We detect this by checking if it's used in allocation context
                // and has a size-related name.
                //
                // "n" is checked separately, per identifier token, against the
                // Hungarian-notation shape this codebase family actually uses for
                // count/size locals: bare `n`/`N`, a short two-letter abbreviation
                // (`nc`, `nb`), or lowercase `n` immediately followed by an
                // uppercase letter or digit (`nNew`, `nBytes`, `nReq`, `n2`) —
                // rather than via substring on the whole argument text.
                // `.contains("n")` over the whole text matches almost any
                // identifier that has the letter anywhere in it (context,
                // CMD_CONNECT, NULL, nodes, lpString, an SQLITE_OPEN_*_JOURNAL
                // flag, ...), which picks the wrong argument out of the call and
                // stops there (`return` below), never reaching the real size
                // expression later in the same call — while still requiring one
                // of these shapes (not a bare substring) keeps matching the very
                // common `nNew`/`nBytes`/`nc`-style names that a plain "is it
                // exactly 'n'" token check would otherwise miss, without also
                // matching ordinary words that merely start with 'n'
                // (`nodes`, `name`, `null`, `new`). The multi-character words
                // don't have the wrong-argument problem to nearly the same
                // degree, so they keep substring matching to still catch size
                // words fused into a larger identifier (`blksize`, `payloadlen`).
                let arg_lower = arg_text.to_lowercase();
                let size_related = ["length", "len", "size", "count", "sz"]
                    .iter()
                    .any(|&name| arg_lower.contains(name))
                    || arg_text.split(|c: char| !c.is_alphanumeric()).any(|token| {
                        if token.eq_ignore_ascii_case("n") {
                            return true;
                        }
                        if !token.starts_with('n') {
                            return false;
                        }
                        token.len() == 2
                            || token
                                .chars()
                                .nth(1)
                                .is_some_and(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                    });

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

/// The name `param` declares and the declarator that declares it. `None`
/// for an unnamed parameter and for a function or function pointer.
fn parameter_name<'s, 't>(param: &Node<'t>, source: &'s str) -> Option<(&'s str, Node<'t>)> {
    let declarator = param.child_by_field_name("declarator")?;
    let mut current = declarator;
    loop {
        match current.kind() {
            "identifier" => return Some((get_node_text(&current, source), declarator)),
            "pointer_declarator"
            | "array_declarator"
            | "parenthesized_declarator"
            | "attributed_declarator" => {
                current = current.child_by_field_name("declarator").or_else(|| {
                    current.named_children(&mut current.walk()).find(|c| {
                        c.kind() != "type_qualifier" && c.kind() != "attribute_declaration"
                    })
                })?;
            }
            _ => return None,
        }
    }
}

/// Whether a word of `name` ends with a size word, or is one with a single
/// letter after it: `len`, `buf_size`, `nMaxCount`, `payloadlen`, `sizep`,
/// `message_lengths`, but not `silent` or `fileName`, which hold `len`
/// inside another word, nor `country`, nor an ordinary word a size word only
/// ends (`account`, `resize`). Words break at `_`, at a digit, and where a
/// lower-case letter meets an upper-case one.
fn names_a_size(name: &str) -> bool {
    const SIZE_WORDS: &[&str] = &["size", "len", "length", "count", "sz"];
    const ORDINARY_WORDS: &[&str] = &[
        "account",
        "discount",
        "miscount",
        "recount",
        "viscount",
        "resize",
        "downsize",
        "upsize",
        "oversize",
        "undersize",
        "outsize",
        "capsize",
        "fallen",
        "stolen",
        "pollen",
        "swollen",
        "sullen",
    ];
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if !c.is_ascii_alphabetic() {
            words.push(std::mem::take(&mut word));
            prev_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower {
            words.push(std::mem::take(&mut word));
        }
        prev_lower = c.is_ascii_lowercase();
        word.push(c.to_ascii_lowercase());
    }
    words.push(word);
    words.iter().any(|w| {
        !ORDINARY_WORDS.contains(&w.as_str())
            && SIZE_WORDS
                .iter()
                .any(|s| w.ends_with(s) || (w.starts_with(s) && w.len() == s.len() + 1))
    })
}

/// Whether an object declared `t` can hold a size: an integer, or a pointer
/// to or array of one, other than a pointer to or array of plain `char`,
/// which is a string. `unsigned char *count` can: a byte-wide counter
/// written through the pointer. A pointer whose pointee is not known can.
fn may_hold_size(t: &CType) -> bool {
    let mut derived = false;
    let mut t = t;
    loop {
        match t {
            CType::Pointer(None) | CType::Array(None) => return true,
            CType::Pointer(Some(inner)) | CType::Array(Some(inner)) => {
                derived = true;
                t = inner;
            }
            CType::Int {
                sign: Sign::PlainChar,
                ..
            } => return !derived,
            _ => return t.is_integer(),
        }
    }
}

/// Whether a type spelling names `size_t` or `rsize_t`, through this file's
/// typedefs: not a pointer to one, and not `ssize_t`.
fn is_size_t_spelling(spelling: &str, typing: &Typing) -> bool {
    let mut spelling = spelling.to_string();
    for _ in 0..8 {
        if spelling.contains('*') || spelling.contains('[') {
            return false;
        }
        let words: Vec<&str> = spelling
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|w| !w.is_empty() && !matches!(*w, "const" | "volatile" | "register"))
            .collect();
        if words.iter().any(|w| matches!(*w, "size_t" | "rsize_t")) {
            return true;
        }
        match words.as_slice() {
            [alias] => match typing.visible.typedef_types.get(*alias) {
                Some(aliased) => spelling = aliased.clone(),
                None => return false,
            },
            _ => return false,
        }
    }
    false
}

/// Whether `node` is typed `size_t` (or `rsize_t`) by declaration: `sizeof`,
/// a name or member declared it, a C library call returning it, or
/// arithmetic on such operands and constants (`strlen(s) + 1`). Arithmetic
/// with any other operand is not, though the usual conversions make
/// `sizeof(*p) + n` a `size_t`: the size `n` is held in its own type, the
/// object the rule asks about. Nor is a cast, which converts a size held in
/// another type (`(size_t)n * 2`), nor an operand whose type is not in reach.
/// A shift is typed by its left operand alone: `len << 1` is `size_t` when
/// `len` is, and `1 << len` is an `int`.
fn is_size_t_typed(node: &Node, source: &str, typing: &Typing) -> bool {
    match node.kind() {
        "sizeof_expression" | "alignof_expression" => true,
        "parenthesized_expression" => node
            .named_child(0)
            .is_some_and(|inner| is_size_t_typed(&inner, source, typing)),
        "identifier" => {
            let name = get_node_text(node, source);
            typing
                .env
                .declarations()
                .and_then(|d| d.resolve_identifier_declared_type_indexed(node, name, source))
                .unwrap_or_else(|| ast_utils::resolve_identifier_declared_type(node, name, source))
                .is_some_and(|spelling| is_size_t_spelling(&spelling, typing))
        }
        "field_expression" => member_is_size_t(node, source, typing),
        "call_expression" => node
            .child_by_field_name("function")
            .filter(|f| f.kind() == "identifier")
            .map(|f| get_node_text(&f, source))
            .is_some_and(|name| SIZE_T_RESULTS.contains(&name) && !typing.redefined.contains(name)),
        "binary_expression" => {
            let op = node
                .child_by_field_name("operator")
                .map(|o| get_node_text(&o, source))
                .unwrap_or("");
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            let (Some(left), Some(right)) = (left, right) else {
                return false;
            };
            let typed = |n: &Node| is_size_t_typed(n, source, typing);
            // A shift has the type of its promoted left operand (C11 6.5.7p3).
            if matches!(op, "<<" | ">>") {
                return typed(&left);
            }
            let operand = |n: &Node| typed(n) || is_constant(n);
            matches!(op, "+" | "-" | "*" | "/" | "%" | "&" | "|" | "^")
                && operand(&left)
                && operand(&right)
                && (typed(&left) || typed(&right))
        }
        "conditional_expression" => {
            let typed = |f: &str| {
                node.child_by_field_name(f)
                    .is_some_and(|n| is_size_t_typed(&n, source, typing))
            };
            typed("consequence") && typed("alternative")
        }
        _ => false,
    }
}

/// Whether `node` is an integer or character constant, parenthesized or not.
fn is_constant(node: &Node) -> bool {
    match node.kind() {
        "number_literal" | "char_literal" => true,
        "parenthesized_expression" => node.named_child(0).is_some_and(|n| is_constant(&n)),
        _ => false,
    }
}

/// Whether the member `field` names is declared `size_t` in the struct its
/// object is typed by.
fn member_is_size_t(field: &Node, source: &str, typing: &Typing) -> bool {
    let (Some(object), Some(member)) = (
        field.child_by_field_name("argument"),
        field.child_by_field_name("field"),
    ) else {
        return false;
    };
    let record = match expr_type::expr_type(&object, source, typing.env) {
        Some(CType::Record(Some(tag))) => tag,
        Some(CType::Pointer(Some(inner))) => match *inner {
            CType::Record(Some(tag)) => tag,
            _ => return false,
        },
        _ => return false,
    };
    let member = get_node_text(&member, source);
    let tag = typing
        .visible
        .struct_typedef_aliases
        .get(&record)
        .cloned()
        .unwrap_or(record);
    let shaped = typing
        .visible
        .struct_field_shapes
        .get(&tag)
        .and_then(|f| f.get(member))
        .is_some_and(|shape| !shape.is_empty());
    !shaped
        && typing
            .visible
            .struct_field_types
            .get(&tag)
            .and_then(|f| f.get(member))
            .is_some_and(|spelling| is_size_t_spelling(spelling, typing))
}
