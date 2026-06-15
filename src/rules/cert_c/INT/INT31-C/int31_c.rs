//! INT31-C: Ensure that integer conversions do not result in lost or misinterpreted data
//!
//! This rule detects integer conversions that may result in lost or misinterpreted data:
//! - Signed to unsigned conversion without checking for negative values
//! - Unsigned to signed conversion without checking for overflow
//! - Narrowing conversions without bounds checking
//! - memset with value > UCHAR_MAX
//! - time_t comparison with -1 without proper cast

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::{self, FunctionCfg};
use crate::analyze::const_eval::{self, MacroConstantMap, VarRangeMap};
use crate::analyze::context::ProjectContext;
use crate::analyze::function_summary::FunctionSummary;
use crate::analyze::value_range::RangeAnalysisResult;
use crate::analyze::vra_access;
use crate::manifest::{RuleCategory, Severity};
use crate::rules::cert_c::int_provenance;
use crate::utility::cert_c::ast_utils::{self, get_node_text, is_function_parameter};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Int31C {
    function_cfgs: RefCell<HashMap<usize, FunctionCfg>>,
    vra_results: RefCell<HashMap<usize, RangeAnalysisResult>>,
    function_summaries: RefCell<HashMap<String, FunctionSummary>>,
    /// Reverse call graph: callee_name → set of caller names.
    callers: RefCell<HashMap<String, HashSet<String>>>,
    /// Globals written by a tainted function — see the INT32-C provenance gate.
    global_writers: RefCell<HashMap<String, HashSet<String>>>,
    /// Per-function memo of risky variable names, keyed by function node id;
    /// cleared per file.
    risky_vars_cache: RefCell<HashMap<usize, HashSet<String>>>,
}

impl Int31C {
    pub fn new() -> Self {
        Self {
            function_cfgs: RefCell::new(HashMap::new()),
            vra_results: RefCell::new(HashMap::new()),
            function_summaries: RefCell::new(HashMap::new()),
            callers: RefCell::new(HashMap::new()),
            global_writers: RefCell::new(HashMap::new()),
            risky_vars_cache: RefCell::new(HashMap::new()),
        }
    }

    /// Opt-in provenance gate for lossy conversions: returns true when the
    /// converted value `operand` derives from untrusted or unbounded input (a
    /// taint source, a full-range parser, an untrusted-decode accessor, a
    /// tainted-summary callee return, or a tainted global). When false, the
    /// value is bounded local state and the conversion is treated as safe —
    /// the same opt-in philosophy as INT30-C/INT32-C, applied to the converted
    /// operand. No-op (returns true) without cross-file context, preserving
    /// legacy behavior and existing tests.
    fn converted_value_is_risky(&self, operand: &Node, source: &str) -> bool {
        let summaries = self.function_summaries.borrow();
        if summaries.is_empty() {
            return true;
        }
        let func = match ast_utils::find_containing_function(operand) {
            Some(f) => f,
            None => return true,
        };
        let body = match func.child_by_field_name("body") {
            Some(b) => b,
            None => return true,
        };
        let func_id = func.id();
        {
            let mut cache = self.risky_vars_cache.borrow_mut();
            cache
                .entry(func_id)
                .or_insert_with(|| int_provenance::collect_risky_vars(&body, &summaries, source));
        }
        let cache = self.risky_vars_cache.borrow();
        let risky_vars = match cache.get(&func_id) {
            Some(s) => s,
            None => return true,
        };
        let global_writers = self.global_writers.borrow();
        int_provenance::operand_is_risky(operand, risky_vars, &summaries, &global_writers, source)
    }

    fn vra_var_ranges_at(&self, expr_node: &Node) -> Option<VarRangeMap> {
        vra_access::var_ranges_entry_at(
            &self.function_cfgs.borrow(),
            &self.vra_results.borrow(),
            expr_node,
        )
    }

    /// Check if VRA proves the source expression fits in the target type at this node.
    /// Returns true if the value is provably safe for the conversion.
    fn vra_proves_conversion_safe(
        &self,
        node: &Node,
        source_expr_node: &Node,
        source: &str,
        _target_type: &str,
        target_width: u32,
        target_signed: bool,
    ) -> bool {
        let var_ranges = match self.vra_var_ranges_at(node) {
            Some(r) => r,
            None => return false,
        };

        let macros = MacroConstantMap::new();
        if let Some(range) =
            const_eval::try_evaluate_range(source_expr_node, source, &macros, &var_ranges)
        {
            if target_signed {
                return range.fits_in_signed(target_width);
            } else {
                return range.fits_in_unsigned(target_width);
            }
        }

        // For identifiers, also try looking up directly by name
        let expr_text = get_node_text(source_expr_node, source).trim().to_string();
        if let Some(&range) = var_ranges.get(&expr_text) {
            if target_signed {
                return range.fits_in_signed(target_width);
            } else {
                return range.fits_in_unsigned(target_width);
            }
        }

        false
    }

    /// Heuristic: is the value of `var_name` in the enclosing function
    /// provably free of any externally-controlled input path?
    ///
    /// A "taint-free" value within a bounded block (`if (var < LIT)`) is
    /// overwhelmingly non-negative in practice, because programs rarely
    /// pair a fixed-source positive literal with a `< LIMIT` guard unless
    /// they mean the value to be a size. Returns true only when:
    /// - the containing function's summary has no taint-source call, AND
    /// - every `var = someFn(...)` assignment in the body targets a callee
    ///   whose summary is also taint-free, AND
    /// - when `var` is a parameter, every caller is taint-free too.
    ///
    /// If any callee, caller, or summary lookup is missing, the check
    /// conservatively returns false (preserving the flag).
    fn var_is_taint_free(&self, node: &Node, var_name: &str, source: &str) -> bool {
        let func = match ast_utils::find_containing_function(node) {
            Some(f) => f,
            None => return false,
        };

        let func_name = match cfg::get_function_name(&func, source) {
            Some(n) => n,
            None => return false,
        };

        let summaries = self.function_summaries.borrow();
        if summaries.is_empty() {
            // No cross-file context — don't second-guess the rule's
            // existing VRA/guard checks.
            return false;
        }

        let func_summary = match summaries.get(func_name) {
            Some(s) => s,
            None => return false,
        };
        if func_summary.has_env03_taint_source {
            return false;
        }

        let body = match func.child_by_field_name("body") {
            Some(b) => b,
            None => return false,
        };

        if body_has_tainted_call_assignment_to(&body, var_name, &summaries, source) {
            return false;
        }

        if is_function_parameter(&func, var_name, source) {
            // Parameter case: defer taint judgement to callers.
            let callers = self.callers.borrow();
            let caller_set = match callers.get(func_name) {
                Some(set) if !set.is_empty() => set,
                _ => return false,
            };
            for caller in caller_set {
                match summaries.get(caller) {
                    Some(s) if !s.has_env03_taint_source => {}
                    _ => return false,
                }
            }
            return true;
        }

        // Local variable: only suppress when we see a call-return assignment
        // from at least one clean callee. Without such evidence the var may
        // have been sourced from a file-scope global, an address-of read,
        // or another channel we can't inspect — stay conservative.
        body_has_any_call_assignment_to(&body, var_name, source)
    }
}

/// Walk `body` looking for any assignment or initializer that stores a
/// call-expression result into `var_name`. If the callee's summary has
/// a taint source, the assignment is tainted — return true.
fn body_has_tainted_call_assignment_to(
    body: &Node,
    var_name: &str,
    summaries: &HashMap<String, FunctionSummary>,
    source: &str,
) -> bool {
    let mut found = false;
    walk_for_tainted_assignment(body, var_name, summaries, source, &mut found);
    found
}

fn walk_for_tainted_assignment(
    node: &Node,
    var_name: &str,
    summaries: &HashMap<String, FunctionSummary>,
    source: &str,
    found: &mut bool,
) {
    if *found {
        return;
    }
    match node.kind() {
        "assignment_expression" => {
            if let Some(lhs) = node.child_by_field_name("left") {
                let lhs_text = get_node_text(&lhs, source).trim();
                if lhs_text == var_name {
                    if let Some(rhs) = node.child_by_field_name("right") {
                        if call_rhs_has_taint_source(&rhs, summaries, source) {
                            *found = true;
                            return;
                        }
                    }
                }
            }
        }
        "init_declarator" => {
            if let Some(decl) = node.child_by_field_name("declarator") {
                if declarator_name_matches(&decl, var_name, source) {
                    if let Some(value) = node.child_by_field_name("value") {
                        if call_rhs_has_taint_source(&value, summaries, source) {
                            *found = true;
                            return;
                        }
                    }
                }
            }
        }
        _ => {}
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            walk_for_tainted_assignment(&child, var_name, summaries, source, found);
            if *found {
                return;
            }
        }
    }
}

/// Returns true when the identifier embedded in a declarator (handling
/// pointer/array wrappers) exactly equals `var_name`.
fn declarator_name_matches(decl: &Node, var_name: &str, source: &str) -> bool {
    let mut current = *decl;
    loop {
        match current.kind() {
            "identifier" | "field_identifier" => {
                return get_node_text(&current, source).trim() == var_name;
            }
            _ => {
                if let Some(inner) = current.child_by_field_name("declarator") {
                    current = inner;
                    continue;
                }
                // Try first named child as fallback
                let mut next = None;
                for i in 0..current.child_count() {
                    if let Some(c) = current.child(i) {
                        if c.is_named() {
                            next = Some(c);
                            break;
                        }
                    }
                }
                match next {
                    Some(n) => current = n,
                    None => return false,
                }
            }
        }
    }
}

/// Walk `body` looking for any assignment or initializer that stores a
/// call-expression result into `var_name`. Returns true if at least one
/// such `var = fn(...)` exists, regardless of the callee's taint status.
fn body_has_any_call_assignment_to(body: &Node, var_name: &str, source: &str) -> bool {
    let mut found = false;
    walk_for_any_call_assignment(body, var_name, source, &mut found);
    found
}

fn walk_for_any_call_assignment(node: &Node, var_name: &str, source: &str, found: &mut bool) {
    if *found {
        return;
    }
    match node.kind() {
        "assignment_expression" => {
            if let Some(lhs) = node.child_by_field_name("left") {
                if get_node_text(&lhs, source).trim() == var_name {
                    if let Some(rhs) = node.child_by_field_name("right") {
                        if unwrap_to_call(rhs).kind() == "call_expression" {
                            *found = true;
                            return;
                        }
                    }
                }
            }
        }
        "init_declarator" => {
            if let Some(decl) = node.child_by_field_name("declarator") {
                if declarator_name_matches(&decl, var_name, source) {
                    if let Some(value) = node.child_by_field_name("value") {
                        if unwrap_to_call(value).kind() == "call_expression" {
                            *found = true;
                            return;
                        }
                    }
                }
            }
        }
        _ => {}
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            walk_for_any_call_assignment(&child, var_name, source, found);
            if *found {
                return;
            }
        }
    }
}

/// Returns true if `rhs` is (or contains at the top level) a call whose
/// callee's summary reports a taint source.
fn call_rhs_has_taint_source(
    rhs: &Node,
    summaries: &HashMap<String, FunctionSummary>,
    source: &str,
) -> bool {
    let call = unwrap_to_call(*rhs);
    if call.kind() != "call_expression" {
        return false;
    }
    let func = match call.child_by_field_name("function") {
        Some(f) => f,
        None => return false,
    };
    let name = get_node_text(&func, source);
    let ident = name
        .rsplit(|c: char| !c.is_alphanumeric() && c != '_')
        .next()
        .unwrap_or(name);
    match summaries.get(ident) {
        // A helper that transitively returns taint (`return recv_wrapper()`)
        // is flagged via `returns_tainted` even when its own body contains
        // no direct taint source.
        Some(s) => s.has_env03_taint_source || s.returns_tainted,
        None => false,
    }
}

fn unwrap_to_call(mut node: Node) -> Node {
    loop {
        match node.kind() {
            "parenthesized_expression" => {
                if let Some(inner) = node.named_child(0) {
                    node = inner;
                    continue;
                }
                break;
            }
            "cast_expression" => {
                if let Some(value) = node.child_by_field_name("value") {
                    node = value;
                    continue;
                }
                break;
            }
            _ => break,
        }
    }
    node
}

/// Returns true when `node` sits inside an `if (ident < N)` / `if (ident <= N)`
/// guard where `N` is a non-negative integer literal (or `ident > -1` style).
/// Looks up through 15 ancestors for the enclosing `if_statement`.
fn is_inside_upper_bound_guard(node: &Node, source: &str, ident: &str) -> bool {
    if ident.is_empty() {
        return false;
    }
    let mut current = *node;
    for _ in 0..15 {
        let parent = match current.parent() {
            Some(p) => p,
            None => break,
        };
        if parent.kind() == "if_statement" {
            if let Some(condition) = parent.child_by_field_name("condition") {
                let cond_text = get_node_text(&condition, source);
                if condition_is_upper_bound_on(cond_text, ident) {
                    return true;
                }
            }
        }
        current = parent;
    }
    false
}

fn condition_is_upper_bound_on(cond: &str, ident: &str) -> bool {
    // Strip parens and whitespace for simpler matching.
    let trimmed = cond.replace([' ', '\t', '\n', '('], "").replace(')', "");
    // Patterns that establish an upper bound on `ident`:
    // - ident<N, ident<=N with N a non-negative literal
    // - N>ident, N>=ident (flipped)
    for op in ["<=", "<"] {
        let needle = format!("{}{}", ident, op);
        if let Some(idx) = trimmed.find(&needle) {
            let rest = &trimmed[idx + needle.len()..];
            if let Some(n) = leading_integer(rest) {
                if n >= 0 {
                    return true;
                }
            }
        }
    }
    for op in [">=", ">"] {
        let needle = format!("{}{}", op, ident);
        if let Some(idx) = trimmed.find(&needle) {
            let before = &trimmed[..idx];
            if let Some(n) = trailing_integer(before) {
                if n >= 0 {
                    return true;
                }
            }
        }
    }
    false
}

fn leading_integer(s: &str) -> Option<i64> {
    let mut end = 0;
    let bytes = s.as_bytes();
    if bytes.first() == Some(&b'-') {
        end = 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 || (end == 1 && bytes[0] == b'-') {
        return None;
    }
    s[..end].parse().ok()
}

fn trailing_integer(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    let mut start = bytes.len();
    while start > 0 && bytes[start - 1].is_ascii_digit() {
        start -= 1;
    }
    if start > 0 && bytes[start - 1] == b'-' {
        start -= 1;
    }
    if start == bytes.len() {
        return None;
    }
    s[start..].parse().ok()
}

/// Returns the bit-width of a known integer type, or None for unknown types.
/// Check 64-bit before 32-bit to prevent "long int" matching "int".
fn get_type_width(type_str: &str) -> Option<u32> {
    let t = type_str.trim();

    // 8-bit types
    if t == "char" || t == "signed char" || t == "unsigned char" || t == "int8_t" || t == "uint8_t"
    {
        return Some(8);
    }

    // 16-bit types
    if t == "short"
        || t == "signed short"
        || t == "unsigned short"
        || t == "short int"
        || t == "signed short int"
        || t == "unsigned short int"
        || t == "int16_t"
        || t == "uint16_t"
    {
        return Some(16);
    }

    // 64-bit types — check BEFORE 32-bit so "long int" doesn't match "int"
    if t == "long"
        || t == "signed long"
        || t == "unsigned long"
        || t == "long int"
        || t == "signed long int"
        || t == "unsigned long int"
        || t == "long long"
        || t == "signed long long"
        || t == "unsigned long long"
        || t == "long long int"
        || t == "signed long long int"
        || t == "unsigned long long int"
        || t == "int64_t"
        || t == "uint64_t"
        || t == "size_t"
        || t == "ssize_t"
        || t == "ptrdiff_t"
        || t == "intptr_t"
        || t == "uintptr_t"
    {
        return Some(64);
    }

    // 32-bit types
    if t == "int"
        || t == "signed"
        || t == "unsigned"
        || t == "signed int"
        || t == "unsigned int"
        || t == "int32_t"
        || t == "uint32_t"
    {
        return Some(32);
    }

    None
}

// Signed integer types
const SIGNED_TYPES: &[&str] = &[
    "signed",
    "int",
    "signed int",
    "short",
    "signed short",
    "long",
    "signed long",
    "long long",
    "signed long long",
    "signed char",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "signed long int",
    "signed short int",
    "ssize_t",
    "ptrdiff_t",
    "intptr_t",
    "intmax_t",
];

// Unsigned integer types
const UNSIGNED_TYPES: &[&str] = &[
    "unsigned",
    "unsigned int",
    "unsigned short",
    "unsigned long",
    "unsigned long long",
    "unsigned char",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "size_t",
    "unsigned long int",
    "unsigned short int",
    "uintptr_t",
    "uintmax_t",
];

// Types ranked by size (smallest to largest) for narrowing detection
const NARROW_TYPES: &[&str] = &["char", "signed char", "unsigned char", "int8_t", "uint8_t"];

const WIDE_TYPES: &[&str] = &[
    // 16-bit types (wider than NARROW_TYPES which are 8-bit)
    "short",
    "unsigned short",
    "short int",
    "unsigned short int",
    "int16_t",
    "uint16_t",
    // 32-bit types
    "int",
    "unsigned",
    "unsigned int",
    "signed int",
    "int32_t",
    "uint32_t",
    // 64-bit types
    "long",
    "unsigned long",
    "long int",
    "unsigned long int",
    "signed long int",
    "long long",
    "unsigned long long",
    "int64_t",
    "uint64_t",
    "size_t",
];

impl CertRule for Int31C {
    fn rule_id(&self) -> &'static str {
        "INT31-C"
    }

    fn description(&self) -> &'static str {
        "Ensure that integer conversions do not result in lost or misinterpreted data"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "INT31-C"
    }

    fn set_function_cfgs(&self, cfgs: &HashMap<usize, FunctionCfg>) {
        *self.function_cfgs.borrow_mut() = cfgs.clone();
    }

    fn set_vra_results(&self, results: &HashMap<usize, RangeAnalysisResult>) {
        *self.vra_results.borrow_mut() = results.clone();
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
        *self.global_writers.borrow_mut() = context.global_writers.clone();

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

    fn needs_vra(&self) -> bool {
        true
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        // Risky-var memo is keyed on tree-sitter node ids, unique only within
        // one parse tree — reset per file.
        self.risky_vars_cache.borrow_mut().clear();
        self.check_function(node, source, &mut violations);
        violations
    }
}

impl Int31C {
    fn check_function(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for function definitions and analyze their bodies
        if node.kind() == "function_definition" {
            if let Some(body) = node.child_by_field_name("body") {
                // Track variable types and validated variables
                let mut var_types: HashMap<String, String> = HashMap::new();
                let mut validated_vars: HashSet<String> = HashSet::new();

                // First: collect parameter types from function declarator
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    self.collect_var_types(&declarator, source, &mut var_types);
                }

                // Then: collect variable types from body
                self.collect_var_types(&body, source, &mut var_types);
                Self::collect_validations(&body, source, &mut validated_vars, &var_types);

                // Second pass: check for unsafe conversions
                self.check_unsafe_conversions(
                    &body,
                    source,
                    violations,
                    &var_types,
                    &validated_vars,
                );
            }
        }

        // Recurse into children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_function(&child, source, violations);
            }
        }
    }

    fn collect_var_types(
        &self,
        node: &Node,
        source: &str,
        var_types: &mut HashMap<String, String>,
    ) {
        // Collect from declarations
        if node.kind() == "declaration" {
            // Extract type from declaration
            if let Some(type_text) = self.find_type_specifier_text(node, source) {
                // Find declarators
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "init_declarator" {
                            if let Some(declarator) = child.child_by_field_name("declarator") {
                                let var_name = Self::extract_var_name(&declarator, source);
                                if !var_name.is_empty() {
                                    var_types.insert(var_name, type_text.clone());
                                }
                            }
                        } else if child.kind() == "identifier" {
                            let var_name = get_node_text(&child, source).to_string();
                            var_types.insert(var_name, type_text.clone());
                        }
                    }
                }
            }
        }

        // Also track from parameter_declarations (function parameters)
        if node.kind() == "parameter_declaration" {
            // For parameters, extract the full type including modifiers
            let type_text = self.extract_parameter_type(node, source);
            if !type_text.is_empty() {
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    let var_name = Self::extract_var_name(&declarator, source);
                    if !var_name.is_empty() {
                        var_types.insert(var_name, type_text);
                    }
                }
            }
        }

        // Recurse
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_var_types(&child, source, var_types);
            }
        }
    }

    fn find_type_specifier_text(&self, node: &Node, source: &str) -> Option<String> {
        // Collect all type-related parts (handles "signed int", "unsigned long", etc.)
        let mut type_parts = Vec::new();

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let kind = child.kind();
                if kind == "primitive_type"
                    || kind == "type_identifier"
                    || kind == "sized_type_specifier"
                {
                    return Some(get_node_text(&child, source).to_string());
                }
                // Also collect type qualifiers and specifiers
                if kind == "type_qualifier" {
                    let text = get_node_text(&child, source).to_string();
                    if text == "signed" || text == "unsigned" {
                        type_parts.push(text);
                    }
                }
            }
        }

        // If we found qualifiers but no main type specifier, look again for primitive_type
        if !type_parts.is_empty() {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    let kind = child.kind();
                    if kind == "primitive_type" {
                        type_parts.push(get_node_text(&child, source).to_string());
                        return Some(type_parts.join(" "));
                    }
                }
            }
        }

        None
    }

    fn extract_parameter_type(&self, node: &Node, source: &str) -> String {
        // Extract full type from parameter declaration by getting text before declarator
        // For "signed int si", we want "signed int"
        if let Some(declarator) = node.child_by_field_name("declarator") {
            let decl_start = declarator.start_byte();
            let param_start = node.start_byte();
            if decl_start > param_start {
                let type_text = &source[param_start..decl_start];
                return type_text.trim().to_string();
            }
        }
        // Fallback to find_type_specifier_text
        self.find_type_specifier_text(node, source)
            .unwrap_or_default()
    }

    fn extract_var_name(node: &Node, source: &str) -> String {
        if node.kind() == "identifier" {
            return get_node_text(node, source).to_string();
        }
        if node.kind() == "pointer_declarator" {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    let name = Self::extract_var_name(&child, source);
                    if !name.is_empty() {
                        return name;
                    }
                }
            }
        }
        String::new()
    }

    fn collect_validations(
        node: &Node,
        source: &str,
        validated_vars: &mut HashSet<String>,
        var_types: &HashMap<String, String>,
    ) {
        // Look for if statements that validate bounds
        if node.kind() == "if_statement" {
            if let Some(condition) = node.child_by_field_name("condition") {
                let cond_text = get_node_text(&condition, source);

                // Check for validations of each tracked variable
                for (var, _var_type) in var_types.iter() {
                    if cond_text.contains(var) {
                        // Check for common validation patterns:
                        // - < 0 (negative check for signed to unsigned)
                        // - > MAX / <= MAX (upper bound for unsigned to signed or narrowing)
                        // - < MIN / >= MIN (lower bound for signed narrowing)
                        let has_bounds_check = (cond_text.contains('<')
                            || cond_text.contains('>')
                            || cond_text.contains("<=")
                            || cond_text.contains(">="))
                            && (cond_text.contains("0")
                                || cond_text.contains("MAX")
                                || cond_text.contains("MIN")
                                || cond_text.contains("_MAX")
                                || cond_text.contains("_MIN"));

                        if has_bounds_check {
                            // The variable is validated if:
                            // 1. There's error handling in consequence (then block) - else block is safe
                            // 2. The conversion happens in the consequence when bounds are validated
                            // 3. There's an alternative (else) that handles errors

                            if let Some(consequence) = node.child_by_field_name("consequence") {
                                let cons_text = get_node_text(&consequence, source);
                                // If error handling in consequence, the else branch is safe
                                if cons_text.contains("return")
                                    || cons_text.contains("Handle error")
                                    || cons_text.contains("error")
                                {
                                    validated_vars.insert(var.clone());
                                }
                                // If the conversion/assignment to var is in consequence after bounds check
                                // (like `if (u_a <= SCHAR_MAX) { sc = (signed char)u_a; }`)
                                // The variable being converted (u_a) is validated for that use
                                if cons_text.contains(var) {
                                    validated_vars.insert(var.clone());
                                }
                            }
                            if let Some(alternative) = node.child_by_field_name("alternative") {
                                let alt_text = get_node_text(&alternative, source);
                                // If assignment is in alternative (else), var is validated
                                if alt_text.contains(var) {
                                    validated_vars.insert(var.clone());
                                }
                                // If else has error handling, then branch is safe
                                if alt_text.contains("Handle error") || alt_text.contains("error") {
                                    validated_vars.insert(var.clone());
                                }
                            }
                        }
                    }
                }
            }
        }

        // Detect bounded constant assignments: data = CHAR_MAX - 5;
        // If a tracked variable is assigned a value referencing a type-limit macro,
        // the programmer is aware of type bounds and subsequent casts are intentional.
        if node.kind() == "expression_statement" {
            if let Some(expr) = node.child(0) {
                if expr.kind() == "assignment_expression" {
                    if let Some(left) = expr.child_by_field_name("left") {
                        let lhs = get_node_text(&left, source).trim().to_string();
                        if var_types.contains_key(&lhs) {
                            if let Some(right) = expr.child_by_field_name("right") {
                                let rhs = get_node_text(&right, source);
                                if Self::rhs_has_narrow_limit_macro(rhs) {
                                    validated_vars.insert(lhs);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Also check init_declarator: int data = CHAR_MAX - 5;
        if node.kind() == "init_declarator" {
            if let Some(declarator) = node.child_by_field_name("declarator") {
                let var_name = Self::extract_var_name(&declarator, source);
                if !var_name.is_empty() {
                    if let Some(value) = node.child_by_field_name("value") {
                        let rhs = get_node_text(&value, source);
                        if Self::rhs_has_narrow_limit_macro(rhs) {
                            validated_vars.insert(var_name);
                        }
                    }
                }
            }
        }

        // Recurse
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                Self::collect_validations(&child, source, validated_vars, var_types);
            }
        }
    }

    /// Check if a right-hand-side expression references a narrow-type limit macro.
    /// Only suppress for macros that bound the value to a narrow (char-sized) range.
    /// Wide-type limits like LONG_MAX or INT_MAX suggest the value may be too large
    /// for a narrowing cast, so those should NOT suppress (e.g., `s_a = LONG_MAX;
    /// (signed char)s_a` is a genuine truncation).
    fn rhs_has_narrow_limit_macro(rhs: &str) -> bool {
        const NARROW_LIMIT_MACROS: &[&str] = &[
            "CHAR_MAX",
            "CHAR_MIN",
            "SCHAR_MAX",
            "SCHAR_MIN",
            "UCHAR_MAX",
            "INT8_MAX",
            "INT8_MIN",
            "UINT8_MAX",
        ];
        NARROW_LIMIT_MACROS.iter().any(|m| rhs.contains(m))
    }

    fn check_unsafe_conversions(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, String>,
        validated_vars: &HashSet<String>,
    ) {
        // Check for memset with value > UCHAR_MAX and signed→size_t in call args
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                let func_name = get_node_text(&func, source);
                if func_name == "memset" {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        self.check_memset_value(&args, node, source, violations);
                    }
                }
            }
            self.check_call_argument_conversion(
                node,
                source,
                violations,
                var_types,
                validated_vars,
            );
        }

        // Check for time_t comparison with uncast -1
        if node.kind() == "binary_expression" {
            self.check_time_t_comparison(node, source, violations, var_types);
        }

        // Check for cast expressions with potential loss of data
        if node.kind() == "cast_expression" {
            self.check_cast_conversion(node, source, violations, var_types, validated_vars);
        }

        // Check for implicit conversion in assignments
        if node.kind() == "assignment_expression" || node.kind() == "init_declarator" {
            self.check_assignment_conversion(node, source, violations, var_types, validated_vars);
        }

        // Recurse
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_unsafe_conversions(
                    &child,
                    source,
                    violations,
                    var_types,
                    validated_vars,
                );
            }
        }
    }

    /// Returns the parameter indices that expect size_t for known standard library functions.
    fn get_size_t_param_positions(func_name: &str) -> Option<&'static [usize]> {
        match func_name {
            "malloc" => Some(&[0]),
            "calloc" => Some(&[0, 1]),
            "realloc" => Some(&[1]),
            "aligned_alloc" => Some(&[0, 1]),
            "memcpy" | "memmove" | "memset" | "memcmp" => Some(&[2]),
            "strncpy" | "strncat" | "strncmp" => Some(&[2]),
            "snprintf" => Some(&[1]),
            "fread" | "fwrite" => Some(&[1, 2]),
            "strnlen" | "wcsnlen" => Some(&[1]),
            "qsort" | "bsearch" => Some(&[2, 3]),
            _ => None,
        }
    }

    /// Check for implicit signed→unsigned conversion in function call arguments
    /// where the parameter expects size_t. This catches CWE-194 (sign extension)
    /// and CWE-195 (signed to unsigned conversion error).
    fn check_call_argument_conversion(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, String>,
        _validated_vars: &HashSet<String>,
    ) {
        let func = match node.child_by_field_name("function") {
            Some(f) => f,
            None => return,
        };
        let func_name = get_node_text(&func, source).to_string();

        let size_t_positions = match Self::get_size_t_param_positions(&func_name) {
            Some(p) => p,
            None => return,
        };

        let args = match node.child_by_field_name("arguments") {
            Some(a) => a,
            None => return,
        };

        // Collect actual argument nodes (skip parens and commas)
        let mut arg_nodes = Vec::new();
        for i in 0..args.child_count() {
            if let Some(child) = args.child(i) {
                if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                    arg_nodes.push(child);
                }
            }
        }

        for &param_idx in size_t_positions {
            if param_idx >= arg_nodes.len() {
                continue;
            }
            let arg_node = &arg_nodes[param_idx];

            // Skip explicit casts — user has acknowledged the conversion
            if arg_node.kind() == "cast_expression" {
                continue;
            }

            // Skip sizeof expressions — always non-negative
            let arg_text = get_node_text(arg_node, source).to_string();
            if arg_node.kind() == "sizeof_expression" || arg_text.contains("sizeof") {
                continue;
            }

            // Skip non-negative literals
            if arg_node.kind() == "number_literal" {
                continue;
            }

            // Determine the argument's declared type via its dominant identifier
            let ident = if arg_node.kind() == "identifier" {
                arg_text.clone()
            } else {
                Self::extract_dominant_identifier(arg_node, source)
            };
            if ident.is_empty() {
                continue;
            }

            let arg_type = match var_types.get(&ident) {
                Some(t) => t.clone(),
                None => continue,
            };

            // Only flag signed types — unsigned→size_t is fine
            if !self.is_signed_type(&arg_type) {
                continue;
            }

            // VRA suppression: if value is provably non-negative, safe for size_t
            if self.vra_proves_conversion_safe(node, arg_node, source, "size_t", 64, false) {
                continue;
            }

            // Suppression: inside a bounds-checked block that validates against
            // a type-limit macro (SHRT_MAX, INT_MAX, SIZE_MAX, etc.)
            if self.is_inside_bounds_checked_block(node, source, &ident) {
                continue;
            }

            // Suppression: enclosed in an if-condition that checks var >= 0
            if Self::is_inside_non_negative_guard(node, source, &ident) {
                continue;
            }

            // Suppression: cross-function taint-free check. If the value is
            // bounded above (via an `if (ident < LIT)` or equivalent guard)
            // and no taint-source call touches the variable — directly, via
            // call-return assignment, or via a caller when `ident` is a
            // parameter — treat as safe.
            if is_inside_upper_bound_guard(node, source, &ident)
                && self.var_is_taint_free(node, &ident, source)
            {
                continue;
            }

            // Opt-in provenance gate (mirrors INT30-C/INT32-C): only flag when
            // the converted value derives from untrusted/unbounded input. A
            // bounded-local signed value is safe to pass to size_t in practice.
            if !self.converted_value_is_risky(arg_node, source) {
                continue;
            }

            let pos = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Signed value '{}' ({}) implicitly converted to size_t in {}() call",
                    ident, arg_type, func_name
                ),
                file_path: String::new(),
                line: pos.row + 1,
                column: pos.column + 1,
                suggestion: Some(
                    "Validate that the value is non-negative before passing to size_t parameter, or use an explicit cast".to_string(),
                ),
                ..Default::default()
            });
        }
    }

    fn check_memset_value(
        &self,
        args_node: &Node,
        call_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // memset(ptr, value, size) - check if value is > 255
        let mut arg_idx = 0;
        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                    if arg_idx == 1 {
                        // This is the value argument
                        let value_text = get_node_text(&child, source);
                        // Check if it's a literal number > 255
                        if let Ok(value) = value_text.parse::<i64>() {
                            if !(0..=255).contains(&value) {
                                let pos = call_node.start_position();
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::High,
                                    message: format!(
                                        "memset value {} will be truncated to unsigned char (0-255)",
                                        value
                                    ),
                                    file_path: String::new(),
                                    line: pos.row + 1,
                                    column: pos.column + 1,
                                    suggestion: Some(
                                        "Use a value in the range 0-255 for memset".to_string(),
                                    ),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                    arg_idx += 1;
                }
            }
        }
    }

    fn check_time_t_comparison(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, String>,
    ) {
        // Check if comparing time_t with -1 without cast
        let node_text = get_node_text(node, source);

        // Look for pattern: time_t_var != -1 or time_t_var == -1
        if let Some(left) = node.child_by_field_name("left") {
            let left_text = get_node_text(&left, source);

            // Check if left is a time_t variable
            let is_time_t = var_types.get(left_text).is_some_and(|t| t == "time_t");

            if is_time_t {
                if let Some(right) = node.child_by_field_name("right") {
                    let right_text = get_node_text(&right, source);

                    // Check if right is -1 without cast
                    if right_text == "-1"
                        || (right_text.starts_with("-") && !right_text.contains("(time_t)"))
                    {
                        // Check if the -1 is properly cast
                        if !node_text.contains("(time_t)") {
                            let pos = node.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::Medium,
                                message: "Comparing time_t with -1 without proper cast".to_string(),
                                file_path: String::new(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                                suggestion: Some("Cast -1 to time_t: (time_t)-1".to_string()),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    fn check_cast_conversion(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, String>,
        validated_vars: &HashSet<String>,
    ) {
        // Get the target type of the cast
        let mut target_type = String::new();
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "type_descriptor" {
                    target_type = get_node_text(&child, source).to_string();
                    break;
                }
            }
        }

        // Get the source expression being cast
        let source_expr = self.get_cast_operand(node, source);

        if target_type.is_empty() || source_expr.is_empty() {
            return;
        }

        // Check if source_expr is a validated variable
        if validated_vars.contains(&source_expr) {
            return;
        }

        // Get source type if known
        let source_type = var_types.get(&source_expr).cloned().unwrap_or_default();
        if source_type.is_empty() {
            // Even without a resolved source type, detect narrowing when the cast
            // operand is a shift expression (e.g., `(uint8_t)(val >> 8)`). A right-shift
            // by >= 8 bits implies the source is at least 16-bit, so casting to uint8_t
            // is a narrowing conversion that may lose data.
            self.check_shift_narrowing(node, source, &source_expr, &target_type, violations);
            return;
        }

        // Check for dangerous conversions
        let target_clean = target_type
            .replace("(", "")
            .replace(")", "")
            .trim()
            .to_string();

        // Skip pointer-type casts — not integer value conversions
        // e.g., (uint8_t *)buf is pointer reinterpretation, not a narrowing conversion
        if target_clean.contains('*') || source_type.contains('*') {
            return;
        }

        let target_width = get_type_width(&target_clean);
        let target_signed = self.is_signed_type(&target_clean);
        let operand_node = self.get_cast_operand_node(node);

        // Opt-in provenance gate (mirrors INT30-C/INT32-C): a cast only loses
        // or misinterprets data dangerously when the converted value is
        // untrusted/unbounded; a bounded-local value is safe. Applies to all
        // three conversion paths below.
        if let Some(ref op_node) = operand_node {
            if !self.converted_value_is_risky(op_node, source) {
                return;
            }
        }

        // Signed to unsigned without validation
        if self.is_signed_type(&source_type) && self.is_unsigned_type(&target_clean) {
            // VRA: if value is provably non-negative and fits in target width, suppress
            if let (Some(tw), Some(ref op_node)) = (target_width, &operand_node) {
                if self.vra_proves_conversion_safe(node, op_node, source, &target_clean, tw, false)
                {
                    return;
                }
            }
            if self.is_inside_bounds_checked_block(node, source, &source_expr) {
                return;
            }
            let pos = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Signed to unsigned conversion of '{}' without bounds check",
                    source_expr
                ),
                file_path: String::new(),
                line: pos.row + 1,
                column: pos.column + 1,
                suggestion: Some(
                    "Check that the value is non-negative before conversion".to_string(),
                ),
                ..Default::default()
            });
        }

        // Unsigned to signed without validation
        if self.is_unsigned_type(&source_type) && self.is_signed_type(&target_clean) {
            // VRA: if value is provably within signed target range, suppress
            if let (Some(tw), Some(ref op_node)) = (target_width, &operand_node) {
                if self.vra_proves_conversion_safe(node, op_node, source, &target_clean, tw, true) {
                    return;
                }
            }
            if self.is_inside_bounds_checked_block(node, source, &source_expr) {
                return;
            }
            let pos = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Unsigned to signed conversion of '{}' without bounds check",
                    source_expr
                ),
                file_path: String::new(),
                line: pos.row + 1,
                column: pos.column + 1,
                suggestion: Some(
                    "Check that the value is within signed range before conversion".to_string(),
                ),
                ..Default::default()
            });
        }

        // Narrowing conversion (wide to narrow)
        if self.is_wide_type(&source_type) && self.is_narrow_type(&target_clean) {
            // VRA: if value provably fits in target type, suppress
            if let (Some(tw), Some(ref op_node)) = (target_width, &operand_node) {
                if self.vra_proves_conversion_safe(
                    node,
                    op_node,
                    source,
                    &target_clean,
                    tw,
                    target_signed,
                ) {
                    return;
                }
            }
            if self.is_inside_bounds_checked_block(node, source, &source_expr) {
                return;
            }
            let pos = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Narrowing conversion of '{}' from {} to {} without bounds check",
                    source_expr, source_type, target_clean
                ),
                file_path: String::new(),
                line: pos.row + 1,
                column: pos.column + 1,
                suggestion: Some(
                    "Check that the value is within target type range before conversion"
                        .to_string(),
                ),
                ..Default::default()
            });
        }
    }

    /// Detect narrowing when a left-shift expression is cast to a narrow type.
    /// Left-shift moves bits up, then narrow cast discards high bits = data loss.
    /// Right-shift before narrow cast is intentional byte extraction and is SAFE:
    ///   `(uint8_t)(val >> 8)` extracts the high byte — no data loss.
    fn check_shift_narrowing(
        &self,
        node: &Node,
        _source: &str,
        source_expr: &str,
        target_type: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let target_clean = target_type
            .replace("(", "")
            .replace(")", "")
            .trim()
            .to_string();
        if !self.is_narrow_type(&target_clean) {
            return;
        }

        // Right-shift before narrow cast = byte extraction = safe (FP-010).
        // Only flag left-shift before narrow cast, which loses high bits.
        if source_expr.contains("<<") && !source_expr.contains(">>") {
            let pos = node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::High,
                message: format!(
                    "Narrowing conversion: '{}' shifted left and cast to {} may lose upper bits",
                    source_expr, target_clean
                ),
                file_path: String::new(),
                line: pos.row + 1,
                column: pos.column + 1,
                suggestion: Some(
                    "Ensure the shifted value fits in the target type or use a wider type"
                        .to_string(),
                ),
                ..Default::default()
            });
        }
    }

    /// Check if a node is inside a bounds-checked block — an enclosing
    /// if-statement (or ternary) whose condition validates the source expression
    /// against a type-limit macro (CHAR_MAX, SCHAR_MIN, UINT8_MAX, etc.).
    fn is_inside_bounds_checked_block(&self, node: &Node, source: &str, source_expr: &str) -> bool {
        const LIMIT_MACROS: &[&str] = &[
            "CHAR_MAX",
            "CHAR_MIN",
            "SCHAR_MAX",
            "SCHAR_MIN",
            "UCHAR_MAX",
            "SHRT_MAX",
            "SHRT_MIN",
            "USHRT_MAX",
            "INT_MAX",
            "INT_MIN",
            "UINT_MAX",
            "LONG_MAX",
            "LONG_MIN",
            "ULONG_MAX",
            "LLONG_MAX",
            "LLONG_MIN",
            "ULLONG_MAX",
            "INT8_MAX",
            "INT8_MIN",
            "UINT8_MAX",
            "INT16_MAX",
            "INT16_MIN",
            "UINT16_MAX",
            "INT32_MAX",
            "INT32_MIN",
            "UINT32_MAX",
            "INT64_MAX",
            "INT64_MIN",
            "UINT64_MAX",
            "SIZE_MAX",
        ];

        if source_expr.is_empty() {
            return false;
        }

        let mut current = *node;
        for _ in 0..15 {
            let parent = match current.parent() {
                Some(p) => p,
                None => break,
            };

            if parent.kind() == "if_statement" {
                if let Some(condition) = parent.child_by_field_name("condition") {
                    let cond_text = get_node_text(&condition, source);

                    let has_comparison = cond_text.contains('<')
                        || cond_text.contains('>')
                        || cond_text.contains("<=")
                        || cond_text.contains(">=");

                    let has_bound = LIMIT_MACROS.iter().any(|m| cond_text.contains(m));

                    let references_operand = cond_text.contains(source_expr);

                    if has_comparison && has_bound && references_operand {
                        return true;
                    }
                }
            }

            // Also check ternary (conditional_expression)
            if parent.kind() == "conditional_expression" {
                if let Some(condition) = parent.child(0) {
                    let cond_text = get_node_text(&condition, source);

                    let has_comparison = cond_text.contains('<') || cond_text.contains('>');
                    let has_bound = LIMIT_MACROS.iter().any(|m| cond_text.contains(m));
                    let references_operand = cond_text.contains(source_expr);

                    if has_comparison && has_bound && references_operand {
                        return true;
                    }
                }
            }

            current = parent;
        }
        false
    }

    /// Check if the node is inside an if-block whose condition verifies the
    /// variable is non-negative: `if (var >= 0)` or `if (0 <= var)`.
    /// This is the proper guard against signed→unsigned conversion issues.
    fn is_inside_non_negative_guard(node: &Node, source: &str, var_name: &str) -> bool {
        let mut current = *node;
        for _ in 0..15 {
            let parent = match current.parent() {
                Some(p) => p,
                None => break,
            };

            if parent.kind() == "if_statement" {
                if let Some(condition) = parent.child_by_field_name("condition") {
                    let cond_text = get_node_text(&condition, source);
                    if cond_text.contains(var_name) {
                        // Check for patterns: var >= 0, var > 0, 0 <= var, 0 < var
                        // Also: var >= 0 && var < LIMIT (compound)
                        let trimmed = cond_text.replace(' ', "");
                        let patterns = [
                            format!("{}>=0", var_name),
                            format!("{}>0", var_name),
                            format!("0<={}", var_name),
                            format!("0<{}", var_name),
                        ];
                        if patterns.iter().any(|p| trimmed.contains(p)) {
                            return true;
                        }
                    }
                }
            }

            current = parent;
        }
        false
    }

    fn get_cast_operand(&self, node: &Node, source: &str) -> String {
        // Find the operand of the cast (skip type_descriptor and parens)
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let kind = child.kind();
                if kind != "type_descriptor" && kind != "(" && kind != ")" {
                    return get_node_text(&child, source).to_string();
                }
            }
        }
        String::new()
    }

    fn get_cast_operand_node<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let kind = child.kind();
                if kind != "type_descriptor" && kind != "(" && kind != ")" {
                    return Some(child);
                }
            }
        }
        None
    }

    fn check_assignment_conversion(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, String>,
        validated_vars: &HashSet<String>,
    ) {
        // Extract LHS name and RHS node depending on node kind
        let (lhs_name, rhs_node) = if node.kind() == "assignment_expression" {
            let left = match node.child_by_field_name("left") {
                Some(l) => l,
                None => return,
            };
            let right = match node.child_by_field_name("right") {
                Some(r) => r,
                None => return,
            };
            (get_node_text(&left, source).trim().to_string(), right)
        } else if node.kind() == "init_declarator" {
            let declarator = match node.child_by_field_name("declarator") {
                Some(d) => d,
                None => return,
            };
            let value = match node.child_by_field_name("value") {
                Some(v) => v,
                None => return,
            };
            (Self::extract_var_name(&declarator, source), value)
        } else {
            return;
        };

        if lhs_name.is_empty() {
            return;
        }

        // Get LHS type from var_types
        let lhs_type = match var_types.get(&lhs_name) {
            Some(t) => t.clone(),
            None => return,
        };

        let lhs_width = match get_type_width(&lhs_type) {
            Some(w) => w,
            None => return,
        };

        let rhs_width = match self.infer_rhs_width(&rhs_node, source, var_types) {
            Some(w) => w,
            None => return,
        };

        // No narrowing
        if rhs_width <= lhs_width {
            return;
        }

        // Suppression: RHS has a narrowing cast whose target width <= LHS width
        // (check_cast_conversion already flags this)
        if Self::rhs_has_narrowing_cast_to(&rhs_node, source, lhs_width) {
            return;
        }

        // Suppression: validated variable
        if validated_vars.contains(&lhs_name) {
            return;
        }

        // VRA suppression: if RHS value provably fits in LHS type, suppress
        let lhs_signed = self.is_signed_type(&lhs_type);
        if self
            .vra_proves_conversion_safe(node, &rhs_node, source, &lhs_type, lhs_width, lhs_signed)
        {
            return;
        }

        // Suppression: inside bounds-checked block
        // Try to extract source expression name for the bounds check
        let rhs_text = get_node_text(&rhs_node, source);
        let source_expr = Self::extract_dominant_identifier(&rhs_node, source);
        if !source_expr.is_empty()
            && self.is_inside_bounds_checked_block(node, source, &source_expr)
        {
            return;
        }

        // Suppression: RHS literal fits in LHS type
        if Self::rhs_literal_fits_in_width(&rhs_node, source, lhs_width) {
            return;
        }

        // Suppression: RHS has safe mask (& 0xFF etc.)
        if Self::rhs_has_safe_mask(&rhs_text, lhs_width) {
            return;
        }

        // Opt-in provenance gate (mirrors INT30-C/INT32-C): only flag a
        // narrowing assignment when the RHS derives from untrusted/unbounded
        // input. A bounded-local wider value rarely actually loses data.
        if !self.converted_value_is_risky(&rhs_node, source) {
            return;
        }

        let pos = node.start_position();
        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "Implicit narrowing conversion: assigning wider type to '{}' ({})",
                lhs_name, lhs_type
            ),
            file_path: String::new(),
            line: pos.row + 1,
            column: pos.column + 1,
            suggestion: Some(
                "Add an explicit bounds check or use an explicit narrowing cast".to_string(),
            ),
            ..Default::default()
        });
    }

    /// Infer the bit-width of the RHS expression.
    fn infer_rhs_width(
        &self,
        node: &Node,
        source: &str,
        var_types: &HashMap<String, String>,
    ) -> Option<u32> {
        match node.kind() {
            "cast_expression" => {
                // Extract the cast target type
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "type_descriptor" {
                            let type_text = get_node_text(&child, source)
                                .replace("(", "")
                                .replace(")", "")
                                .trim()
                                .to_string();
                            return get_type_width(&type_text);
                        }
                    }
                }
                None
            }
            "identifier" => {
                let name = get_node_text(node, source).to_string();
                var_types.get(&name).and_then(|t| get_type_width(t))
            }
            "parenthesized_expression" => {
                // Unwrap parens and recurse
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() != "(" && child.kind() != ")" {
                            return self.infer_rhs_width(&child, source, var_types);
                        }
                    }
                }
                None
            }
            "number_literal" => None,
            _ => None,
        }
    }

    /// Check if RHS is a cast_expression whose target width <= LHS width.
    /// If so, check_cast_conversion() already handles it — don't double-flag.
    fn rhs_has_narrowing_cast_to(node: &Node, source: &str, lhs_width: u32) -> bool {
        let check = node;
        if check.kind() == "cast_expression" {
            for i in 0..check.child_count() {
                if let Some(child) = check.child(i) {
                    if child.kind() == "type_descriptor" {
                        let type_text = get_node_text(&child, source)
                            .replace("(", "")
                            .replace(")", "")
                            .trim()
                            .to_string();
                        if let Some(cast_width) = get_type_width(&type_text) {
                            return cast_width <= lhs_width;
                        }
                    }
                }
            }
        }
        // Also check through parenthesized expressions
        if check.kind() == "parenthesized_expression" {
            for i in 0..check.child_count() {
                if let Some(child) = check.child(i) {
                    if child.kind() != "(" && child.kind() != ")" {
                        return Self::rhs_has_narrowing_cast_to(&child, source, lhs_width);
                    }
                }
            }
        }
        false
    }

    /// Check if RHS is a number literal that fits in the given bit width.
    fn rhs_literal_fits_in_width(node: &Node, source: &str, width: u32) -> bool {
        let check = if node.kind() == "parenthesized_expression" {
            // Unwrap one level of parens
            let mut inner = None;
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() != "(" && child.kind() != ")" {
                        inner = Some(child);
                        break;
                    }
                }
            }
            match inner {
                Some(n) => n,
                None => return false,
            }
        } else {
            *node
        };

        if check.kind() != "number_literal" {
            return false;
        }

        let text = get_node_text(&check, source).trim().to_string();
        // Strip suffixes (U, L, UL, LL, ULL, etc.)
        let cleaned = text.trim_end_matches(['u', 'U', 'l', 'L']);

        let value = if cleaned.starts_with("0x") || cleaned.starts_with("0X") {
            i64::from_str_radix(&cleaned[2..], 16).ok()
        } else if cleaned.starts_with("0b") || cleaned.starts_with("0B") {
            i64::from_str_radix(&cleaned[2..], 2).ok()
        } else if cleaned.starts_with('0') && cleaned.len() > 1 && !cleaned.contains('.') {
            i64::from_str_radix(cleaned, 8).ok()
        } else {
            cleaned.parse::<i64>().ok()
        };

        match value {
            Some(v) => match width {
                8 => (0..=255).contains(&v) || (-128..=127).contains(&v),
                16 => (0..=65535).contains(&v) || (-32768..=32767).contains(&v),
                32 => (0..=4294967295i64).contains(&v) || (-2147483648..=2147483647).contains(&v),
                _ => true,
            },
            None => false,
        }
    }

    /// Check if RHS text contains a safe bitmask that limits the value to fit in `width` bits.
    fn rhs_has_safe_mask(rhs_text: &str, width: u32) -> bool {
        if !rhs_text.contains('&') {
            return false;
        }

        let masks: &[&str] = match width {
            8 => &["0xFF", "0xff", "0XFF", "0Xff", "255"],
            16 => &[
                "0xFFFF", "0xffff", "0XFFFF", "0Xffff", "65535", "0xFF", "0xff", "255",
            ],
            32 => &[
                "0xFFFFFFFF",
                "0xffffffff",
                "0xFFFF",
                "0xffff",
                "0xFF",
                "0xff",
            ],
            _ => return false,
        };

        masks.iter().any(|m| rhs_text.contains(m))
    }

    /// Extract the dominant identifier from an expression for bounds-check lookup.
    /// For `(uint16_t)(buffer[i])`, this extracts "buffer".
    /// For `some_var`, this extracts "some_var".
    fn extract_dominant_identifier(node: &Node, source: &str) -> String {
        match node.kind() {
            "identifier" => get_node_text(node, source).to_string(),
            "cast_expression" => {
                // Get the operand (skip type_descriptor and parens)
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        let kind = child.kind();
                        if kind != "type_descriptor" && kind != "(" && kind != ")" {
                            return Self::extract_dominant_identifier(&child, source);
                        }
                    }
                }
                String::new()
            }
            "parenthesized_expression" => {
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() != "(" && child.kind() != ")" {
                            return Self::extract_dominant_identifier(&child, source);
                        }
                    }
                }
                String::new()
            }
            _ => {
                // For complex expressions, try to find the first identifier child
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "identifier" {
                            return get_node_text(&child, source).to_string();
                        }
                    }
                }
                String::new()
            }
        }
    }

    fn is_signed_type(&self, type_str: &str) -> bool {
        let normalized = type_str.to_lowercase();

        // First check if it's explicitly unsigned - if so, not signed
        // This catches "unsigned int", "unsigned long", etc.
        if normalized.contains("unsigned") {
            return false;
        }

        // Also bail out for unsigned stdint types (uint32_t contains "int" as substring)
        if self.is_unsigned_type(type_str) {
            return false;
        }

        // Check for explicit signed types
        for t in SIGNED_TYPES {
            if normalized.contains(&t.to_lowercase()) {
                return true;
            }
        }

        // Plain "int" without unsigned qualifier is signed
        if normalized == "int" || normalized.ends_with(" int") {
            return true;
        }
        false
    }

    fn is_unsigned_type(&self, type_str: &str) -> bool {
        let normalized = type_str.to_lowercase();

        // Must explicitly contain "unsigned"
        if normalized.contains("unsigned") {
            return true;
        }

        // Check for unsigned types by name (size_t, uint8_t, etc.)
        for t in UNSIGNED_TYPES {
            let t_lower = t.to_lowercase();
            // Only match if the type doesn't also match a signed pattern
            if normalized.contains(&t_lower)
                && !t_lower.contains("signed")
                && (t_lower.starts_with("u") || t_lower.contains("size"))
            {
                return true;
            }
        }
        false
    }

    fn is_narrow_type(&self, type_str: &str) -> bool {
        let normalized = type_str.to_lowercase();
        for t in NARROW_TYPES {
            if normalized.contains(&t.to_lowercase()) {
                return true;
            }
        }
        false
    }

    fn is_wide_type(&self, type_str: &str) -> bool {
        let normalized = type_str.to_lowercase();
        for t in WIDE_TYPES {
            if normalized.contains(&t.to_lowercase()) {
                return true;
            }
        }
        false
    }
}
