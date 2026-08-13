//! Lightweight constant evaluation and value-range analysis for macro constants.
//!
//! Resolves `#define` macro constants and propagates value ranges through
//! arithmetic expressions. Used by INT32-C and INT30-C to suppress false
//! positives when expressions provably fit within type limits.
//!
//! This is NOT a full CFG-based dataflow — it's syntactic constant folding
//! plus loop-bound ancestor walks.

use std::collections::HashMap;
use std::sync::LazyLock;
use tree_sitter::Node;

/// Map of macro name → constant integer value.
pub type MacroConstantMap = HashMap<String, i64>;

/// Map of variable name → value range.
pub type VarRangeMap = HashMap<String, ValueRange>;

/// An integer value range [min, max].
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ValueRange {
    pub min: i64,
    pub max: i64,
}

impl ValueRange {
    pub fn exact(val: i64) -> Self {
        Self { min: val, max: val }
    }

    pub fn new(min: i64, max: i64) -> Self {
        Self { min, max }
    }

    pub fn add(&self, other: &ValueRange) -> Option<Self> {
        let min = self.min.checked_add(other.min)?;
        let max = self.max.checked_add(other.max)?;
        Some(Self { min, max })
    }

    pub fn sub(&self, other: &ValueRange) -> Option<Self> {
        let min = self.min.checked_sub(other.max)?;
        let max = self.max.checked_sub(other.min)?;
        Some(Self { min, max })
    }

    pub fn mul(&self, other: &ValueRange) -> Option<Self> {
        // For multiplication, all four corners must be checked
        let corners = [
            self.min.checked_mul(other.min)?,
            self.min.checked_mul(other.max)?,
            self.max.checked_mul(other.min)?,
            self.max.checked_mul(other.max)?,
        ];
        Some(Self {
            min: *corners.iter().min().unwrap(),
            max: *corners.iter().max().unwrap(),
        })
    }

    pub fn shl(&self, other: &ValueRange) -> Option<Self> {
        if other.max > 63 || other.max < 0 {
            return None;
        }
        // Clamp negative lower bound to 0: negative shifts are UB in C,
        // so in correct code only the non-negative range is reachable.
        let shift_min = other.min.max(0);
        let other = ValueRange::new(shift_min, other.max);
        let corners = [
            self.min.checked_shl(other.min as u32)?,
            self.min.checked_shl(other.max as u32)?,
            self.max.checked_shl(other.min as u32)?,
            self.max.checked_shl(other.max as u32)?,
        ];
        Some(Self {
            min: *corners.iter().min().unwrap(),
            max: *corners.iter().max().unwrap(),
        })
    }

    /// Bitwise AND range: `self & other`.
    ///
    /// For non-negative operands the result is bounded by `min(self.max, other.max)` —
    /// the classical mask-upper-bound approximation.  Returns `None` when either
    /// operand may be negative (signed bitwise AND is implementation-defined in C).
    pub fn bitand(&self, other: &ValueRange) -> Option<Self> {
        if self.min < 0 || other.min < 0 {
            return None;
        }
        Some(Self {
            min: 0,
            max: self.max.min(other.max),
        })
    }

    /// Returns true if every value in this range fits in a signed integer of the given bit width.
    pub fn fits_in_signed(&self, bits: u32) -> bool {
        if bits == 0 || bits > 64 {
            return false;
        }
        if bits == 64 {
            return true; // i64 always fits in 64-bit signed
        }
        let type_min = -(1i64 << (bits - 1));
        let type_max = (1i64 << (bits - 1)) - 1;
        self.min >= type_min && self.max <= type_max
    }

    /// Returns true if every value in this range fits in an unsigned integer of the given bit width.
    pub fn fits_in_unsigned(&self, bits: u32) -> bool {
        if bits == 0 || bits > 64 {
            return false;
        }
        if self.min < 0 {
            return false;
        }
        if bits >= 64 {
            return true;
        }
        let type_max = (1i64 << bits) - 1;
        self.max <= type_max
    }
}

// ---------------------------------------------------------------------------
// Built-in C standard limit macros (<limits.h>, <stdint.h>)
// ---------------------------------------------------------------------------

/// Returns a map of C standard limit macros to their platform values.
/// Uses LP64 data model (64-bit long) which is standard on modern Linux/macOS.
/// Lazily-initialized built-in C limit macros — allocated once, reused across all files.
static BUILTIN_LIMIT_MACROS: LazyLock<MacroConstantMap> = LazyLock::new(|| {
    let mut m = MacroConstantMap::new();
    // <limits.h> — char
    m.insert("CHAR_BIT".into(), 8);
    m.insert("CHAR_MAX".into(), 127);
    m.insert("CHAR_MIN".into(), -128);
    m.insert("SCHAR_MAX".into(), 127);
    m.insert("SCHAR_MIN".into(), -128);
    m.insert("UCHAR_MAX".into(), 255);
    // <limits.h> — short (16-bit)
    m.insert("SHRT_MAX".into(), 32767);
    m.insert("SHRT_MIN".into(), -32768);
    m.insert("USHRT_MAX".into(), 65535);
    // <limits.h> — int (32-bit)
    m.insert("INT_MAX".into(), 2147483647);
    m.insert("INT_MIN".into(), -2147483648);
    m.insert("UINT_MAX".into(), 4294967295);
    // <limits.h> — long (64-bit on LP64)
    m.insert("LONG_MAX".into(), i64::MAX);
    m.insert("LONG_MIN".into(), i64::MIN);
    // <limits.h> — long long (64-bit)
    m.insert("LLONG_MAX".into(), i64::MAX);
    m.insert("LLONG_MIN".into(), i64::MIN);
    // <stdint.h> — fixed-width
    m.insert("INT8_MAX".into(), 127);
    m.insert("INT8_MIN".into(), -128);
    m.insert("INT16_MAX".into(), 32767);
    m.insert("INT16_MIN".into(), -32768);
    m.insert("INT32_MAX".into(), 2147483647);
    m.insert("INT32_MIN".into(), -2147483648);
    m.insert("INT64_MAX".into(), i64::MAX);
    m.insert("INT64_MIN".into(), i64::MIN);
    m.insert("UINT8_MAX".into(), 255);
    m.insert("UINT16_MAX".into(), 65535);
    m.insert("UINT32_MAX".into(), 4294967295);
    m
});

// ---------------------------------------------------------------------------
// sizeof resolution
// ---------------------------------------------------------------------------

/// Resolve sizeof(type) to a constant value.
/// Uses conservative sizes (LP64 model). Returns None for unknown types.
fn resolve_sizeof_type(type_text: &str) -> Option<i64> {
    let t = type_text.trim();
    match t {
        "char" | "signed char" | "unsigned char" | "int8_t" | "uint8_t" | "bool" | "_Bool" => {
            Some(1)
        }
        "short" | "short int" | "signed short" | "unsigned short" | "int16_t" | "uint16_t" => {
            Some(2)
        }
        "int" | "signed int" | "unsigned int" | "signed" | "unsigned" | "int32_t" | "uint32_t"
        | "wchar_t" | "float" => Some(4),
        "long"
        | "signed long"
        | "unsigned long"
        | "long int"
        | "signed long int"
        | "unsigned long int"
        | "long long"
        | "signed long long"
        | "unsigned long long"
        | "long long int"
        | "signed long long int"
        | "unsigned long long int"
        | "int64_t"
        | "uint64_t"
        | "size_t"
        | "ssize_t"
        | "ptrdiff_t"
        | "double"
        | "time_t"
        | "off_t" => Some(8),
        "long double" => Some(16),
        _ => {
            // Pointer types: any type ending with '*' is pointer-sized (8 on LP64)
            if t.ends_with('*') {
                Some(8)
            } else {
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Macro constant collection
// ---------------------------------------------------------------------------

/// Collect `#define NAME "string"` patterns and return a map from name → raw quoted value.
/// Used to check whether a macro expands to an absolute path string.
pub fn collect_string_literal_macros(root: &Node, source: &str) -> HashMap<String, String> {
    let mut raw_defs: Vec<(String, String)> = Vec::new();
    collect_preproc_defs(root, source, &mut raw_defs);

    let mut string_macros = HashMap::new();
    for (name, value) in raw_defs {
        let v = value.trim();
        if v.starts_with('"') && v.ends_with('"') && v.len() >= 2 {
            string_macros.insert(name, v.to_string());
        } else if v.starts_with("L\"") && v.ends_with('"') && v.len() >= 3 {
            // Wide string literal L"..." — strip the L prefix, keep "..."
            string_macros.insert(name, v[1..].to_string());
        }
    }
    string_macros
}

fn is_absolute_path_inner(inner: &str) -> bool {
    inner.starts_with('/')
        || (inner.len() >= 3
            && inner
                .chars()
                .next()
                .map(|c| c.is_ascii_alphabetic())
                .unwrap_or(false)
            && inner.chars().nth(1) == Some(':')
            && (inner.chars().nth(2) == Some('\\') || inner.chars().nth(2) == Some('/')))
        || inner.starts_with("\\\\")
}

/// Return true if `name` is a macro whose value is a relative-path OS command string —
/// non-empty, not starting with a space or dash (argument fragment), and not an absolute path.
/// This distinguishes `BAD_OS_COMMAND = "ls -la"` (relative command) from
/// `SAFE_CMD_ARGS = " -la"` (argument fragment) and `GOOD_OS_COMMAND = "/usr/bin/ls"` (absolute).
pub fn is_relative_command_macro(string_macros: &HashMap<String, String>, name: &str) -> bool {
    let Some(value) = string_macros.get(name) else {
        return false;
    };
    let inner = &value[1..value.len() - 1];
    // Must be non-empty after trimming
    if inner.trim().is_empty() {
        return false;
    }
    // Starts with space or dash → argument fragment, not a standalone command
    if inner.starts_with(' ') || inner.starts_with('-') {
        return false;
    }
    // Absolute path → safe
    !is_absolute_path_inner(inner)
}

/// Return true if `name` is a macro whose string value is safe to use as a
/// `strcpy`/`strcat` source for a command variable. Safe means either an
/// absolute-path macro or an argument-fragment macro (value starts with
/// whitespace or `–` — these are option strings appended to an established path,
/// never standalone relative-command names).
pub fn is_safe_command_macro(string_macros: &HashMap<String, String>, name: &str) -> bool {
    let Some(value) = string_macros.get(name) else {
        return false;
    };
    let inner = &value[1..value.len() - 1];
    // Absolute path → safe
    if is_absolute_path_inner(inner) {
        return true;
    }
    // Empty string → safe (no-op strcat)
    if inner.is_empty() {
        return true;
    }
    // Argument fragment (starts with space or dash) → safe to append
    inner.starts_with(' ') || inner.starts_with('-')
}

/// Collect `#define ALIAS func_name` patterns where the value is a single C identifier.
/// These represent macro aliases for function names (e.g., `#define SYSTEM system`).
/// Returns a map from alias → target identifier.
pub fn collect_macro_aliases(root: &Node, source: &str) -> HashMap<String, String> {
    let mut raw_defs: Vec<(String, String)> = Vec::new();
    collect_preproc_defs(root, source, &mut raw_defs);

    let mut aliases = HashMap::new();
    for (name, value) in &raw_defs {
        let v = value.trim();
        // A function alias is a single C identifier (no operators, parens, digits-only, etc.)
        if !v.is_empty()
            && v.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !v.chars().next().unwrap_or('0').is_ascii_digit()
            // Skip pure integer strings (they're constants, not function aliases)
            && v.parse::<i64>().is_err()
        {
            aliases.insert(name.clone(), v.to_string());
        }
    }
    aliases
}

/// Walk `preproc_def` nodes in the AST to collect `#define NAME value` constants.
/// Handles decimal, hex, octal literals, expressions, and references to other macros.
/// Recurses into `preproc_ifdef/if/ifndef` blocks.
/// Includes built-in C standard limit macros (CHAR_MAX, INT_MAX, etc.).
pub fn collect_macro_constants(root: &Node, source: &str) -> MacroConstantMap {
    let mut macros = BUILTIN_LIMIT_MACROS.clone();
    // Two-pass: first collect all raw definitions, then resolve references
    let mut raw_defs: Vec<(String, String)> = Vec::new();
    collect_preproc_defs(root, source, &mut raw_defs);
    // Also collect file-scope `static const int NAME = VALUE;` declarations
    collect_static_const_defs(root, source, &mut raw_defs);
    // Also collect file-scope `static int NAME = VALUE;` (no const) when never reassigned
    collect_non_const_static_defs(root, source, &mut raw_defs);
    // Collect `enum { NAME = VALUE, ... }` enumerators as compile-time constants
    collect_enum_constants(root, source, &mut raw_defs);

    // Iteratively resolve — handles forward references and chains
    let mut changed = true;
    let mut iterations = 0;
    while changed && iterations < 5 {
        changed = false;
        iterations += 1;
        for (name, value_text) in &raw_defs {
            if macros.contains_key(name) {
                continue;
            }
            if let Some(val) = try_evaluate_text(value_text.trim(), &macros) {
                macros.insert(name.clone(), val);
                changed = true;
            }
        }
    }
    macros
}

/// Collect raw `#define NAME value` pairs from the AST.
fn collect_preproc_defs(node: &Node, source: &str, defs: &mut Vec<(String, String)>) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "preproc_def" => {
                    // preproc_def has children: name (identifier), value (preproc_arg)
                    let name = child
                        .child_by_field_name("name")
                        .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                        .unwrap_or("")
                        .to_string();
                    let value = child
                        .child_by_field_name("value")
                        .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    if !name.is_empty() && !value.is_empty() {
                        // Skip function-like macros (have parenthesized params)
                        if !value.starts_with('(')
                            || value.chars().filter(|&c| c == '(').count()
                                == value.chars().filter(|&c| c == ')').count()
                        {
                            defs.push((name, value));
                        }
                    }
                }
                // Recurse into nested preproc constructs (#if/#ifdef bodies),
                // ERROR nodes, and extern "C" linkage blocks:
                //
                // - ERROR: a single unrelated syntax error elsewhere in a
                //   large #ifndef-guarded block can make tree-sitter-c fall
                //   back to one giant ERROR node wrapping the rest of the
                //   file -- the `preproc_def` children underneath are still
                //   individually well-formed and worth collecting even
                //   though their ancestor is an error-recovery node.
                // - linkage_specification/declaration_list: the standard
                //   `#ifdef __cplusplus extern "C" { #endif ... }` C/C++
                //   interop idiom (virtually every public C header) parses
                //   as a `linkage_specification` whose body is a
                //   `declaration_list` -- without recursing into these, EVERY
                //   #define inside that near-universal wrapper (i.e. most of
                //   the file, in practice) was invisible to macro-constant
                //   collection (task 453, found via curl.h's CURLINFO_*
                //   macros all sitting inside its `extern "C" { ... }` block).
                kind if kind.starts_with("preproc_")
                    || kind == "ERROR"
                    || kind == "linkage_specification"
                    || kind == "declaration_list" =>
                {
                    collect_preproc_defs(&child, source, defs);
                }
                _ => {}
            }
        }
    }
}

/// Collect file-scope `static const int NAME = VALUE;` and `const int NAME = VALUE;`
/// declarations. These behave as compile-time constants in C.
fn collect_static_const_defs(root: &Node, source: &str, defs: &mut Vec<(String, String)>) {
    for i in 0..root.child_count() {
        let child = match root.child(i) {
            Some(c) => c,
            None => continue,
        };
        if child.kind() != "declaration" {
            continue;
        }
        let decl_text = child.utf8_text(source.as_bytes()).unwrap_or("").to_string();
        // Must contain "const" and an integer/bool type
        if !decl_text.contains("const") {
            continue;
        }
        // Check for integer type keywords
        let has_int_type = decl_text.contains("int")
            || decl_text.contains("long")
            || decl_text.contains("short")
            || decl_text.contains("char")
            || decl_text.contains("_Bool");
        if !has_int_type {
            continue;
        }
        // Extract init_declarator children for `NAME = VALUE`
        for j in 0..child.named_child_count() {
            let gc = match child.named_child(j) {
                Some(c) => c,
                None => continue,
            };
            if gc.kind() != "init_declarator" {
                continue;
            }
            // Look for identifier and value
            let mut name = None;
            let mut value = None;
            for k in 0..gc.named_child_count() {
                if let Some(ggc) = gc.named_child(k) {
                    if ggc.kind() == "identifier" && name.is_none() {
                        name = ggc.utf8_text(source.as_bytes()).ok().map(|s| s.to_string());
                    } else if ggc.kind() == "number_literal" && name.is_some() {
                        value = ggc.utf8_text(source.as_bytes()).ok().map(|s| s.to_string());
                    }
                }
            }
            if let (Some(n), Some(v)) = (name, value) {
                defs.push((n, v));
            }
        }
    }
}

/// Collect file-scope `static int NAME = VALUE;` declarations (no `const`) that
/// are never reassigned in the file. These behave as effective compile-time
/// constants in Juliet and similar controlled test patterns.
fn collect_non_const_static_defs(root: &Node, source: &str, defs: &mut Vec<(String, String)>) {
    let mut candidates: Vec<(String, String, usize)> = Vec::new();

    for i in 0..root.child_count() {
        let child = match root.child(i) {
            Some(c) => c,
            None => continue,
        };
        if child.kind() != "declaration" {
            continue;
        }
        let decl_text = child.utf8_text(source.as_bytes()).unwrap_or("");
        // Must have `static` but NOT `const` (const handled by collect_static_const_defs)
        if !decl_text.contains("static") || decl_text.contains("const") {
            continue;
        }
        let has_int_type = decl_text.contains("int")
            || decl_text.contains("long")
            || decl_text.contains("short")
            || decl_text.contains("_Bool");
        if !has_int_type {
            continue;
        }
        let decl_end = child.end_byte();

        for j in 0..child.named_child_count() {
            let gc = match child.named_child(j) {
                Some(c) => c,
                None => continue,
            };
            if gc.kind() != "init_declarator" {
                continue;
            }
            let mut name = None;
            let mut value = None;
            for k in 0..gc.named_child_count() {
                if let Some(ggc) = gc.named_child(k) {
                    if ggc.kind() == "identifier" && name.is_none() {
                        name = ggc.utf8_text(source.as_bytes()).ok().map(|s| s.to_string());
                    } else if ggc.kind() == "number_literal" && name.is_some() {
                        value = ggc.utf8_text(source.as_bytes()).ok().map(|s| s.to_string());
                    }
                }
            }
            if let (Some(n), Some(v)) = (name, value) {
                candidates.push((n, v, decl_end));
            }
        }
    }

    let source_bytes = source.as_bytes();
    for (name, value, decl_end) in candidates {
        if !static_var_assigned_after(source_bytes, &name, decl_end) {
            defs.push((name, value));
        }
    }
}

/// Return true if `name` appears as an assignment target after `after_offset` bytes.
/// Checks for `=` (not `==`), compound assignments, and `++`/`--`.
fn static_var_assigned_after(source: &[u8], name: &str, after_offset: usize) -> bool {
    let name_b = name.as_bytes();
    let n = source.len();
    let m = name_b.len();

    let mut i = after_offset;
    while i + m <= n {
        if &source[i..i + m] != name_b {
            i += 1;
            continue;
        }
        // Word boundary before
        let before_ok = i == 0 || {
            let b = source[i - 1];
            !b.is_ascii_alphanumeric() && b != b'_'
        };
        let after_pos = i + m;
        // Word boundary after
        let after_ok = after_pos >= n || {
            let b = source[after_pos];
            !b.is_ascii_alphanumeric() && b != b'_'
        };
        if before_ok && after_ok {
            let mut j = after_pos;
            while j < n && (source[j] == b' ' || source[j] == b'\t') {
                j += 1;
            }
            if j < n {
                let next = source[j];
                let is_assign = next == b'=' && (j + 1 >= n || source[j + 1] != b'=');
                let is_compound =
                    matches!(next, b'+' | b'-' | b'*' | b'/' | b'%' | b'&' | b'|' | b'^')
                        && j + 1 < n
                        && source[j + 1] == b'=';
                let is_inc = (next == b'+' && j + 1 < n && source[j + 1] == b'+')
                    || (next == b'-' && j + 1 < n && source[j + 1] == b'-');
                if is_assign || is_compound || is_inc {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

/// Collect enumerator names + value expressions from any `enum { ... }` in the
/// tree. Enumerators without an explicit value inherit `previous + 1` (default
/// C semantics), seeded at `0` at the start of each enum body.
fn collect_enum_constants(root: &Node, source: &str, defs: &mut Vec<(String, String)>) {
    fn walk(node: &Node, source: &str, defs: &mut Vec<(String, String)>) {
        if node.kind() == "enumerator_list" {
            let mut prev_name: Option<String> = None;
            let mut implicit_idx: i64 = 0;
            for i in 0..node.named_child_count() {
                let Some(e) = node.named_child(i) else {
                    continue;
                };
                if e.kind() != "enumerator" {
                    continue;
                }
                let name = e
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                    .map(str::to_string);
                let value = e
                    .child_by_field_name("value")
                    .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                    .map(str::to_string);

                if let Some(n) = name {
                    let expr = match value {
                        Some(v) => {
                            implicit_idx = 1;
                            prev_name = Some(n.clone());
                            v.trim().to_string()
                        }
                        None => {
                            let expr = match &prev_name {
                                Some(p) => format!("{} + {}", p, implicit_idx),
                                None => implicit_idx.to_string(),
                            };
                            implicit_idx += 1;
                            expr
                        }
                    };
                    defs.push((n, expr));
                }
            }
        }
        for i in 0..node.child_count() {
            if let Some(c) = node.child(i) {
                walk(&c, source, defs);
            }
        }
    }
    walk(root, source, defs);
}

/// Public wrapper around `try_evaluate_text` for callers that already hold
/// the expression as a textual snippet (e.g., substrings of a condition).
pub fn try_evaluate_text_public(text: &str, macros: &MacroConstantMap) -> Option<i64> {
    try_evaluate_text(text, macros)
}

/// Try to evaluate a text string as an integer constant expression.
/// Handles: decimal, hex, octal literals, macro references, simple arithmetic.
fn try_evaluate_text(text: &str, macros: &MacroConstantMap) -> Option<i64> {
    let text = text.trim();
    // Strip trailing C++ line comments (tree-sitter includes them in preproc_arg)
    let text = if let Some(pos) = text.find("//") {
        text[..pos].trim()
    } else {
        text
    };
    if text.is_empty() {
        return None;
    }
    // Strip trailing type suffixes: U, L, UL, LL, ULL (case-insensitive)
    let text = strip_integer_suffix(text);

    // Strip outer parentheses (handles nested like ((10)))
    let mut text = text;
    loop {
        if text.starts_with('(') && text.ends_with(')') {
            let inner = &text[1..text.len() - 1];
            if parens_balanced(inner) {
                text = inner.trim();
                continue;
            }
        }
        break;
    }

    // Try as a literal
    if let Some(val) = parse_integer_literal(text) {
        return Some(val);
    }

    // Try as a macro reference
    if is_c_identifier(text) {
        return macros.get(text).copied();
    }

    // Try sizeof(type_or_expr) — resolve known types exactly, fall back to
    // conservative minimum of 1 for unknown identifiers (sizeof >= 1 always).
    if let Some(inner) = strip_sizeof_call(text) {
        if let Some(sz) = resolve_sizeof_type(inner) {
            return Some(sz);
        }
        // Unknown type/variable: sizeof(x) >= 1 on all platforms
        if is_c_identifier(inner) {
            return Some(1);
        }
    }

    // Try simple binary expressions: A op B
    // Search for operator from right to left (respecting precedence: +/- before */<<)
    if let Some(val) = try_evaluate_binary_text(text, macros) {
        return Some(val);
    }

    // Try unary negation
    if let Some(rest) = text.strip_prefix('-') {
        let rest = rest.trim();
        if let Some(val) = try_evaluate_text(rest, macros) {
            return val.checked_neg();
        }
    }

    None
}

/// Extract the inner text from a sizeof(...) call in text form.
fn strip_sizeof_call(text: &str) -> Option<&str> {
    let rest = text.strip_prefix("sizeof")?;
    let rest = rest.trim();
    if rest.starts_with('(') && rest.ends_with(')') {
        Some(rest[1..rest.len() - 1].trim())
    } else {
        None
    }
}

/// Try to evaluate a binary expression in text form.
fn try_evaluate_binary_text(text: &str, macros: &MacroConstantMap) -> Option<i64> {
    // Scan for lowest-precedence operators first (+, -), then (*, /), then (<<, >>)
    // Scan right-to-left for left-associativity
    let bytes = text.as_bytes();
    let mut paren_depth = 0i32;

    // Pass 1: + and - (lowest precedence)
    let mut i = bytes.len();
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b')' => paren_depth += 1,
            b'(' => paren_depth -= 1,
            b'+' | b'-' if paren_depth == 0 && i > 0 => {
                // Make sure it's not part of << or >>
                if bytes[i] == b'-' && i > 0 && bytes[i - 1] == b'>' {
                    continue; // -> operator
                }
                let left = text[..i].trim();
                let right = text[i + 1..].trim();
                if !left.is_empty() && !right.is_empty() {
                    let lv = try_evaluate_text(left, macros)?;
                    let rv = try_evaluate_text(right, macros)?;
                    return if bytes[i] == b'+' {
                        lv.checked_add(rv)
                    } else {
                        lv.checked_sub(rv)
                    };
                }
            }
            _ => {}
        }
    }

    // Pass 2: * and /
    paren_depth = 0;
    i = bytes.len();
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b')' => paren_depth += 1,
            b'(' => paren_depth -= 1,
            b'*' | b'/' if paren_depth == 0 && i > 0 => {
                let left = text[..i].trim();
                let right = text[i + 1..].trim();
                if !left.is_empty() && !right.is_empty() {
                    let lv = try_evaluate_text(left, macros)?;
                    let rv = try_evaluate_text(right, macros)?;
                    return if bytes[i] == b'*' {
                        lv.checked_mul(rv)
                    } else if rv == 0 {
                        None
                    } else {
                        Some(lv / rv)
                    };
                }
            }
            _ => {}
        }
    }

    // Pass 3: << and >>
    paren_depth = 0;
    i = bytes.len();
    while i > 1 {
        i -= 1;
        match bytes[i] {
            b')' => paren_depth += 1,
            b'(' => paren_depth -= 1,
            b'<' if paren_depth == 0 && i > 0 && bytes[i - 1] == b'<' => {
                let left = text[..i - 1].trim();
                let right = text[i + 1..].trim();
                if !left.is_empty() && !right.is_empty() {
                    let lv = try_evaluate_text(left, macros)?;
                    let rv = try_evaluate_text(right, macros)?;
                    if !(0..=63).contains(&rv) {
                        return None;
                    }
                    return lv.checked_shl(rv as u32);
                }
                i -= 1; // skip the first <
            }
            b'>' if paren_depth == 0 && i > 0 && bytes[i - 1] == b'>' => {
                let left = text[..i - 1].trim();
                let right = text[i + 1..].trim();
                if !left.is_empty() && !right.is_empty() {
                    let lv = try_evaluate_text(left, macros)?;
                    let rv = try_evaluate_text(right, macros)?;
                    if !(0..=63).contains(&rv) {
                        return None;
                    }
                    return Some(lv >> rv);
                }
                i -= 1;
            }
            _ => {}
        }
    }

    None
}

// ---------------------------------------------------------------------------
// AST-based constant folding
// ---------------------------------------------------------------------------

/// Try to evaluate an AST expression node to an exact integer value.
pub fn try_evaluate_expr(node: &Node, source: &str, macros: &MacroConstantMap) -> Option<i64> {
    match node.kind() {
        "number_literal" => {
            let text = node.utf8_text(source.as_bytes()).ok()?;
            let trimmed = strip_integer_suffix(text.trim());
            parse_integer_literal(trimmed).or_else(|| {
                // Fallback: parse float literals (e.g., 0.0F, 2.0, 1e-40) and truncate to i64.
                // Enables VRA to track float variable assignments for zero-checking.
                let cleaned = trimmed
                    .trim_end_matches('f')
                    .trim_end_matches('F')
                    .trim_end_matches('l')
                    .trim_end_matches('L');
                cleaned.parse::<f64>().ok().map(|f| f as i64)
            })
        }
        "char_literal" => {
            let text = node.utf8_text(source.as_bytes()).ok()?;
            parse_char_literal(text.trim()).map(|c| c as i64)
        }
        "identifier" => {
            let name = node.utf8_text(source.as_bytes()).ok()?;
            macros.get(name).copied()
        }
        "parenthesized_expression" => {
            let inner = node.child(1)?; // skip '('
            try_evaluate_expr(&inner, source, macros)
        }
        "binary_expression" => {
            let left = node.child_by_field_name("left")?;
            let right = node.child_by_field_name("right")?;
            let op = node.child_by_field_name("operator").or_else(|| {
                // tree-sitter C grammar: operator is sometimes an unnamed child
                for i in 0..node.child_count() {
                    if let Some(c) = node.child(i) {
                        let k = c.kind();
                        if matches!(
                            k,
                            "+" | "-"
                                | "*"
                                | "/"
                                | "%"
                                | "<<"
                                | ">>"
                                | "=="
                                | "!="
                                | "<"
                                | ">"
                                | "<="
                                | ">="
                        ) {
                            return Some(c);
                        }
                    }
                }
                None
            })?;
            let op_text = op.utf8_text(source.as_bytes()).ok()?;
            let lv = try_evaluate_expr(&left, source, macros)?;
            let rv = try_evaluate_expr(&right, source, macros)?;
            match op_text {
                "+" => lv.checked_add(rv),
                "-" => lv.checked_sub(rv),
                "*" => lv.checked_mul(rv),
                "/" => {
                    if rv == 0 {
                        None
                    } else {
                        Some(lv / rv)
                    }
                }
                "%" => {
                    if rv == 0 {
                        None
                    } else {
                        Some(lv % rv)
                    }
                }
                "<<" => {
                    if !(0..=63).contains(&rv) {
                        None
                    } else {
                        lv.checked_shl(rv as u32)
                    }
                }
                ">>" => {
                    if !(0..=63).contains(&rv) {
                        None
                    } else {
                        Some(lv >> rv)
                    }
                }
                "==" => Some(if lv == rv { 1 } else { 0 }),
                "!=" => Some(if lv != rv { 1 } else { 0 }),
                "<" => Some(if lv < rv { 1 } else { 0 }),
                ">" => Some(if lv > rv { 1 } else { 0 }),
                "<=" => Some(if lv <= rv { 1 } else { 0 }),
                ">=" => Some(if lv >= rv { 1 } else { 0 }),
                _ => None,
            }
        }
        "unary_expression" => {
            let arg = node.child_by_field_name("argument")?;
            let op = node
                .child_by_field_name("operator")
                .or_else(|| node.child(0))?;
            let op_text = op.utf8_text(source.as_bytes()).ok()?;
            let val = try_evaluate_expr(&arg, source, macros)?;
            match op_text {
                "-" => val.checked_neg(),
                "+" => Some(val),
                "~" => Some(!val),
                "!" => Some(if val == 0 { 1 } else { 0 }),
                _ => None,
            }
        }
        "cast_expression" => {
            // (type)expr — evaluate the inner expression
            let value = node.child_by_field_name("value")?;
            try_evaluate_expr(&value, source, macros)
        }
        "sizeof_expression" => {
            // sizeof(type) or sizeof(expr)
            resolve_sizeof_node(node, source)
        }
        "call_expression" => {
            // Zero-argument calls to known constant functions (e.g., staticReturnsTrue())
            let func = node.child_by_field_name("function")?;
            if func.kind() != "identifier" {
                return None;
            }
            let name = func.utf8_text(source.as_bytes()).ok()?;
            let args = node.child_by_field_name("arguments")?;
            if args.named_child_count() != 0 {
                return None;
            }
            macros.get(name).copied()
        }
        _ => None,
    }
}

/// Resolve a sizeof_expression AST node to a constant value.
fn resolve_sizeof_node(node: &Node, source: &str) -> Option<i64> {
    // sizeof_expression children: "sizeof" "(" type_descriptor ")" or "sizeof" "(" expression ")"
    // The type is in a parenthesized_expression or type_descriptor child.
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "type_descriptor" | "primitive_type" | "sized_type_specifier" => {
                    let type_text = child.utf8_text(source.as_bytes()).ok()?;
                    return resolve_sizeof_type(type_text);
                }
                "parenthesized_expression" => {
                    // sizeof(expr) — check if inner is a type-like identifier
                    if let Some(inner) = child.child(1) {
                        if inner.kind() == "identifier" {
                            let text = inner.utf8_text(source.as_bytes()).ok()?;
                            // Could be a typedef name like wchar_t, int64_t, etc.
                            return resolve_sizeof_type(text);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Range evaluation
// ---------------------------------------------------------------------------

/// Evaluate an AST expression node to a value range.
/// Falls back to `var_ranges` for identifiers not in macros.
pub fn try_evaluate_range(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    var_ranges: &VarRangeMap,
) -> Option<ValueRange> {
    // First try exact evaluation
    if let Some(val) = try_evaluate_expr(node, source, macros) {
        return Some(ValueRange::exact(val));
    }

    match node.kind() {
        "identifier" => {
            let name = node.utf8_text(source.as_bytes()).ok()?;
            if let Some(&val) = macros.get(name) {
                return Some(ValueRange::exact(val));
            }
            var_ranges.get(name).copied()
        }
        "parenthesized_expression" => {
            let inner = node.child(1)?;
            try_evaluate_range(&inner, source, macros, var_ranges)
        }
        "binary_expression" => {
            let left = node.child_by_field_name("left")?;
            let right = node.child_by_field_name("right")?;
            let op = node.child_by_field_name("operator").or_else(|| {
                for i in 0..node.child_count() {
                    if let Some(c) = node.child(i) {
                        let k = c.kind();
                        if matches!(k, "+" | "-" | "*" | "/" | "%" | "<<" | ">>" | "&") {
                            return Some(c);
                        }
                    }
                }
                None
            })?;
            let op_text = op.utf8_text(source.as_bytes()).ok()?;

            // Bitwise AND: `expr & MASK` or `MASK & expr`.
            // For a non-negative constant mask M, the result is always in [0, M]
            // regardless of the other operand — even if that operand's range
            // cannot be computed (e.g. overflows in arithmetic).  This lets VRA
            // prove that `(SHA256_WORD_BITS - b) & SHA256_WORD_MASK` ∈ [0, 31]
            // when SHA256_WORD_MASK = 31.
            if op_text == "&" {
                let lr = try_evaluate_range(&left, source, macros, var_ranges);
                let rr = try_evaluate_range(&right, source, macros, var_ranges);
                return match (lr, rr) {
                    (Some(l), Some(r)) => l.bitand(&r),
                    // One side unknown, other is a known non-negative constant mask.
                    (None, Some(r)) if r.min == r.max && r.min >= 0 => {
                        Some(ValueRange::new(0, r.min))
                    }
                    (Some(l), None) if l.min == l.max && l.min >= 0 => {
                        Some(ValueRange::new(0, l.min))
                    }
                    _ => None,
                };
            }

            let lr = try_evaluate_range(&left, source, macros, var_ranges)?;
            let rr = try_evaluate_range(&right, source, macros, var_ranges)?;
            match op_text {
                "+" => lr.add(&rr),
                "-" => lr.sub(&rr),
                "*" => lr.mul(&rr),
                "<<" => lr.shl(&rr),
                _ => None,
            }
        }
        "unary_expression" => {
            let arg = node.child_by_field_name("argument")?;
            let op = node
                .child_by_field_name("operator")
                .or_else(|| node.child(0))?;
            let op_text = op.utf8_text(source.as_bytes()).ok()?;
            let r = try_evaluate_range(&arg, source, macros, var_ranges)?;
            match op_text {
                "-" => Some(ValueRange::new(r.max.checked_neg()?, r.min.checked_neg()?)),
                "+" => Some(r),
                _ => None,
            }
        }
        "cast_expression" => {
            let value = node.child_by_field_name("value")?;
            try_evaluate_range(&value, source, macros, var_ranges)
        }
        "sizeof_expression" => resolve_sizeof_node(node, source).map(ValueRange::exact),
        // Struct member access: obj.field or obj->field.
        // Try to bound by the declared type of the field by searching the source for
        // `uint8_t fieldName` / `uint16_t fieldName` etc. in struct definitions.
        "field_expression" => {
            if let Some(field_node) = node.child_by_field_name("field") {
                let field_name = field_node.utf8_text(source.as_bytes()).ok()?;
                bound_from_field_type(field_name, source)
            } else {
                None
            }
        }
        "update_expression" => {
            // data++ / data-- / ++data / --data
            let arg = node.child_by_field_name("argument")?;
            let op = node.child_by_field_name("operator").or_else(|| {
                // Operator may be first or last child depending on prefix/postfix
                for i in 0..node.child_count() {
                    if let Some(c) = node.child(i) {
                        let k = c.kind();
                        if k == "++" || k == "--" {
                            return Some(c);
                        }
                    }
                }
                None
            })?;
            let op_text = op.utf8_text(source.as_bytes()).ok()?;
            let r = try_evaluate_range(&arg, source, macros, var_ranges)?;
            let one = ValueRange::exact(1);
            match op_text {
                "++" => r.add(&one),
                "--" => r.sub(&one),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Search the source for a struct field declaration matching `field_name` and
/// return a conservative `ValueRange` based on the declared type.
/// This allows VRA to bound struct field accesses by their declared type width
/// (e.g., `uint8_t length` → [0, 255]) without full struct-type resolution.
fn bound_from_field_type(field_name: &str, source: &str) -> Option<ValueRange> {
    // Narrow integer types with known bounds
    const TYPE_BOUNDS: &[(&str, i64)] = &[
        ("uint8_t", 255),
        ("int8_t", 127),
        ("uint16_t", 65535),
        ("int16_t", 32767),
    ];
    for line in source.lines() {
        let trimmed = line.trim();
        // Look for lines like `uint8_t fieldName;` or `uint8_t fieldName,`
        // within struct definitions. Simple text match — false positives are
        // suppressive (safe), false negatives leave the violation in place.
        for (type_name, max_val) in TYPE_BOUNDS {
            if trimmed.contains(type_name) && trimmed.contains(field_name) {
                // Verify the field name appears after the type (rough word-boundary check)
                if let Some(type_pos) = trimmed.find(type_name) {
                    let after_type = &trimmed[type_pos + type_name.len()..];
                    if after_type.contains(field_name) {
                        let min_val = if type_name.starts_with('u') {
                            0
                        } else {
                            -(*max_val) - 1
                        };
                        return Some(ValueRange::new(min_val, *max_val));
                    }
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Loop-bound extraction
// ---------------------------------------------------------------------------

/// Extract value ranges for variables bounded by enclosing loop conditions.
/// Walks AST ancestors looking for `for`/`while` statements and extracts
/// `var < BOUND` or `var <= BOUND` patterns.
pub fn extract_loop_var_ranges(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
) -> VarRangeMap {
    let mut ranges = VarRangeMap::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "while_statement" | "do_statement" => {
                if let Some(condition) = parent.child_by_field_name("condition") {
                    extract_bound_from_condition(&condition, source, macros, &mut ranges);
                }
            }
            "for_statement" => {
                // Extract upper bound from condition
                if let Some(condition) = parent.child_by_field_name("condition") {
                    extract_bound_from_condition(&condition, source, macros, &mut ranges);
                }
                // Extract lower bound from initializer
                if let Some(initializer) = parent.child_by_field_name("initializer") {
                    extract_init_from_for(&initializer, source, macros, &mut ranges);
                }
            }
            "function_definition" | "translation_unit" => break,
            _ => {}
        }
        current = parent.parent();
    }
    ranges
}

/// Extract variable bounds from a loop condition expression.
/// Handles: `var < expr`, `var <= expr`, `expr > var`, `expr >= var`.
/// Also handles compound `&&` conditions by extracting bounds from each sub-expression.
fn extract_bound_from_condition(
    condition: &Node,
    source: &str,
    macros: &MacroConstantMap,
    ranges: &mut VarRangeMap,
) {
    // Unwrap parenthesized_expression
    let cond = if condition.kind() == "parenthesized_expression" {
        condition.child(1).unwrap_or(*condition)
    } else {
        *condition
    };

    if cond.kind() != "binary_expression" {
        return;
    }

    // Handle compound && conditions: extract bounds from each side
    let op = get_operator_text(&cond, source);
    if op == "&&" {
        if let Some(left) = cond.child_by_field_name("left") {
            extract_bound_from_condition(&left, source, macros, ranges);
        }
        if let Some(right) = cond.child_by_field_name("right") {
            extract_bound_from_condition(&right, source, macros, ranges);
        }
        return;
    }
    let left = match cond.child_by_field_name("left") {
        Some(n) => n,
        None => return,
    };
    let right = match cond.child_by_field_name("right") {
        Some(n) => n,
        None => return,
    };

    let op = get_operator_text(&cond, source);

    match op.as_str() {
        "<"
            // var < BOUND → var in [0, BOUND-1] (assuming non-negative loop counter)
            if left.kind() == "identifier" => {
                if let Some(bound) = try_evaluate_expr(&right, source, macros) {
                    let var_name = left.utf8_text(source.as_bytes()).unwrap_or("");
                    if !var_name.is_empty() {
                        let entry = ranges
                            .entry(var_name.to_string())
                            .or_insert(ValueRange::new(0, bound - 1));
                        // Tighten upper bound if this condition is more restrictive
                        if bound - 1 < entry.max {
                            entry.max = bound - 1;
                        }
                    }
                }
            }
        "<="
            if left.kind() == "identifier" => {
                if let Some(bound) = try_evaluate_expr(&right, source, macros) {
                    let var_name = left.utf8_text(source.as_bytes()).unwrap_or("");
                    if !var_name.is_empty() {
                        let entry = ranges
                            .entry(var_name.to_string())
                            .or_insert(ValueRange::new(0, bound));
                        if bound < entry.max {
                            entry.max = bound;
                        }
                    }
                }
            }
        ">"
            // BOUND > var → same as var < BOUND
            if right.kind() == "identifier" => {
                if let Some(bound) = try_evaluate_expr(&left, source, macros) {
                    let var_name = right.utf8_text(source.as_bytes()).unwrap_or("");
                    if !var_name.is_empty() {
                        let entry = ranges
                            .entry(var_name.to_string())
                            .or_insert(ValueRange::new(0, bound - 1));
                        if bound - 1 < entry.max {
                            entry.max = bound - 1;
                        }
                    }
                }
            }
        ">="
            if right.kind() == "identifier" => {
                if let Some(bound) = try_evaluate_expr(&left, source, macros) {
                    let var_name = right.utf8_text(source.as_bytes()).unwrap_or("");
                    if !var_name.is_empty() {
                        let entry = ranges
                            .entry(var_name.to_string())
                            .or_insert(ValueRange::new(0, bound));
                        if bound < entry.max {
                            entry.max = bound;
                        }
                    }
                }
            }
        _ => {}
    }
}

/// Extract initializer value from a for-loop init clause.
fn extract_init_from_for(
    init: &Node,
    source: &str,
    macros: &MacroConstantMap,
    ranges: &mut VarRangeMap,
) {
    // Handle `int var = expr` (declaration) or `var = expr` (assignment_expression)
    match init.kind() {
        "declaration" => {
            for i in 0..init.child_count() {
                if let Some(child) = init.child(i) {
                    if child.kind() == "init_declarator" {
                        if let (Some(declarator), Some(value)) = (
                            child.child_by_field_name("declarator"),
                            child.child_by_field_name("value"),
                        ) {
                            let var_name = declarator
                                .utf8_text(source.as_bytes())
                                .unwrap_or("")
                                .to_string();
                            if !var_name.is_empty() {
                                if let Some(val) = try_evaluate_expr(&value, source, macros) {
                                    if let Some(range) = ranges.get_mut(&var_name) {
                                        range.min = val;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        "assignment_expression" => {
            if let (Some(left), Some(right)) = (
                init.child_by_field_name("left"),
                init.child_by_field_name("right"),
            ) {
                if left.kind() == "identifier" {
                    let var_name = left.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                    if !var_name.is_empty() {
                        if let Some(val) = try_evaluate_expr(&right, source, macros) {
                            if let Some(range) = ranges.get_mut(&var_name) {
                                range.min = val;
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Local variable resolution
// ---------------------------------------------------------------------------

/// Scan backward in the enclosing compound_statement for assignments to `var_name`
/// and try to evaluate the RHS as a range.
pub fn resolve_local_var_range(
    var_name: &str,
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    loop_ranges: &VarRangeMap,
) -> Option<ValueRange> {
    resolve_local_var_range_depth(var_name, node, source, macros, loop_ranges, 0)
}

fn resolve_local_var_range_depth(
    var_name: &str,
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    loop_ranges: &VarRangeMap,
    depth: u32,
) -> Option<ValueRange> {
    // Find the enclosing compound_statement (function body or block)
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "compound_statement" {
            // Scan statements before our node, keeping the LAST assignment
            // (not the first) since later assignments overwrite earlier ones.
            // If the last modification is unevaluable (e.g., data = rand(),
            // or fscanf(stdin, "%d", &data)), return None so callers don't
            // use a stale range from an earlier assignment.
            let node_start = node.start_byte();
            let mut last_range: Option<ValueRange> = None;
            let mut invalidated = false;
            for i in 0..parent.child_count() {
                if let Some(stmt) = parent.child(i) {
                    if stmt.start_byte() >= node_start {
                        break;
                    }
                    // Check for evaluable assignment (data = CONST or data = expr)
                    if let Some(range) = check_stmt_for_var_assignment(
                        &stmt,
                        var_name,
                        source,
                        macros,
                        loop_ranges,
                        depth,
                    ) {
                        last_range = Some(range);
                        invalidated = false;
                    } else if stmt_modifies_var(&stmt, var_name, source) {
                        // Assignment found but RHS unevaluable (e.g., rand()),
                        // or variable modified through pointer (e.g., fscanf(&var))
                        last_range = None;
                        invalidated = true;
                    }
                }
            }
            if invalidated {
                return None;
            }
            if last_range.is_some() {
                return last_range;
            }
        }
        if parent.kind() == "function_definition" {
            break;
        }
        current = parent.parent();
    }
    None
}

/// Check a single statement for an assignment to `var_name` and return its range.
/// When the RHS is a bare identifier and `depth < 3`, recursively resolves the
/// identifier's value so that copy chains like `int dataCopy = data; int data = dataCopy`
/// are traced back to their original literal source.
fn check_stmt_for_var_assignment(
    stmt: &Node,
    var_name: &str,
    source: &str,
    macros: &MacroConstantMap,
    loop_ranges: &VarRangeMap,
    depth: u32,
) -> Option<ValueRange> {
    match stmt.kind() {
        "expression_statement" => {
            check_assignment_expr_for_var(stmt, var_name, source, macros, loop_ranges, depth)
        }
        "declaration" => {
            check_init_declarator_for_var(stmt, var_name, source, macros, loop_ranges, depth)
        }
        // Control-flow wrappers: scan the compound body for evaluable assignments.
        // Returns the last evaluable assignment found, or None if the body contains
        // any unevaluable modification (e.g., fscanf(&var)) — which triggers the
        // caller's `stmt_modifies_var` fallback and marks the variable as invalidated.
        // This handles goodG2B patterns like `for(h=0;h<1;h++) { data = 2; }` where
        // stmt_modifies_var correctly recognizes the modification but the loop body
        // contains only a simple literal assignment.
        "for_statement" | "while_statement" | "do_statement" | "if_statement" => {
            check_control_flow_body_for_var(stmt, var_name, source, macros, loop_ranges, depth)
        }
        _ => None,
    }
}

/// Resolve a candidate RHS expression against a value-tracked variable:
/// evaluate it directly, or (up to depth 3) recurse through a same-named
/// identifier RHS to resolve *its* assigned range.
fn resolve_var_rhs(
    rhs: &Node,
    stmt: &Node,
    source: &str,
    macros: &MacroConstantMap,
    loop_ranges: &VarRangeMap,
    depth: u32,
) -> Option<ValueRange> {
    if let Some(r) = try_evaluate_range(rhs, source, macros, loop_ranges) {
        return Some(r);
    }
    if rhs.kind() == "identifier" && depth < 3 {
        let rhs_name = rhs.utf8_text(source.as_bytes()).unwrap_or("");
        return resolve_local_var_range_depth(
            rhs_name,
            stmt,
            source,
            macros,
            loop_ranges,
            depth + 1,
        );
    }
    None
}

/// `"expression_statement"` case of [`check_stmt_for_var_assignment`]: find
/// an `assignment_expression` whose LHS is `var_name` and resolve its RHS.
fn check_assignment_expr_for_var(
    stmt: &Node,
    var_name: &str,
    source: &str,
    macros: &MacroConstantMap,
    loop_ranges: &VarRangeMap,
    depth: u32,
) -> Option<ValueRange> {
    for i in 0..stmt.child_count() {
        let child = stmt.child(i)?;
        if child.kind() != "assignment_expression" {
            continue;
        }
        let (Some(left), Some(right)) = (
            child.child_by_field_name("left"),
            child.child_by_field_name("right"),
        ) else {
            continue;
        };
        if left.kind() != "identifier" {
            continue;
        }
        let name = left.utf8_text(source.as_bytes()).unwrap_or("");
        if name == var_name {
            return resolve_var_rhs(&right, stmt, source, macros, loop_ranges, depth);
        }
    }
    None
}

/// `"declaration"` case of [`check_stmt_for_var_assignment`]: find an
/// `init_declarator` declaring `var_name` and resolve its init value.
fn check_init_declarator_for_var(
    stmt: &Node,
    var_name: &str,
    source: &str,
    macros: &MacroConstantMap,
    loop_ranges: &VarRangeMap,
    depth: u32,
) -> Option<ValueRange> {
    for i in 0..stmt.child_count() {
        let child = stmt.child(i)?;
        if child.kind() != "init_declarator" {
            continue;
        }
        let (Some(declarator), Some(value)) = (
            child.child_by_field_name("declarator"),
            child.child_by_field_name("value"),
        ) else {
            continue;
        };
        let name = extract_leaf_identifier(&declarator, source);
        if name == var_name {
            return resolve_var_rhs(&value, stmt, source, macros, loop_ranges, depth);
        }
    }
    None
}

/// Control-flow-wrapper case of [`check_stmt_for_var_assignment`]: scan a
/// `for`/`while`/`do`/`if` statement's compound body for evaluable
/// assignments to `var_name`, bailing to `None` on an inner-scope shadow or
/// an unevaluable modification.
fn check_control_flow_body_for_var(
    stmt: &Node,
    var_name: &str,
    source: &str,
    macros: &MacroConstantMap,
    loop_ranges: &VarRangeMap,
    depth: u32,
) -> Option<ValueRange> {
    for i in 0..stmt.child_count() {
        let child = stmt.child(i)?;
        if child.kind() != "compound_statement" {
            continue;
        }
        if compound_declares_var(&child, var_name, source) {
            return None; // inner-scope shadow — don't evaluate
        }
        let mut last_range: Option<ValueRange> = None;
        for j in 0..child.child_count() {
            let Some(inner) = child.child(j) else {
                continue;
            };
            if let Some(r) =
                check_stmt_for_var_assignment(&inner, var_name, source, macros, loop_ranges, depth)
            {
                last_range = Some(r);
            } else if stmt_modifies_var(&inner, var_name, source) {
                return None; // unevaluable modification in body
            }
        }
        return last_range;
    }
    None
}

/// Check if a statement modifies `var_name` in a way that `check_stmt_for_var_assignment`
/// couldn't evaluate. Covers:
/// - Direct assignment with unevaluable RHS: `var = rand();`, `var = RAND32();`
/// - Pointer modification via function call: `fscanf(stdin, "%d", &var);`
/// - Modifications inside control flow wrappers: `if(1) { fscanf(..., &var); }`
fn stmt_modifies_var(stmt: &Node, var_name: &str, source: &str) -> bool {
    match stmt.kind() {
        "expression_statement" => {
            for i in 0..stmt.child_count() {
                if let Some(child) = stmt.child(i) {
                    // Direct assignment: var = <unevaluable>
                    if child.kind() == "assignment_expression" {
                        if let Some(left) = child.child_by_field_name("left") {
                            if left.kind() == "identifier" {
                                let name = left.utf8_text(source.as_bytes()).unwrap_or("");
                                if name == var_name {
                                    return true;
                                }
                            }
                        }
                    }
                    // Pointer modification: func(..., &var, ...)
                    if child.kind() == "call_expression" {
                        if call_takes_address_of(&child, var_name, source) {
                            return true;
                        }
                    }
                }
            }
        }
        "declaration" => {
            for i in 0..stmt.child_count() {
                if let Some(child) = stmt.child(i) {
                    if child.kind() == "init_declarator" {
                        if let Some(declarator) = child.child_by_field_name("declarator") {
                            let name = extract_leaf_identifier(&declarator, source);
                            if name == var_name && child.child_by_field_name("value").is_some() {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        // Control-flow wrappers: recurse into bodies so that tainted assignments inside
        // if(1)/while/for blocks are not invisible to the backward scan. This prevents
        // `resolve_local_var_range` from returning a stale pre-taint range.
        // We skip compound_statement bodies that declare var_name (inner scope shadow)
        // so that `int data = dataCopy;` blocks don't invalidate the outer `data`.
        "if_statement" | "while_statement" | "for_statement" | "do_statement"
        | "switch_statement" => {
            for i in 0..stmt.child_count() {
                if let Some(child) = stmt.child(i) {
                    match child.kind() {
                        // Skip if this block declares var_name (shadow)
                        "compound_statement"
                            if !compound_declares_var(&child, var_name, source) =>
                        {
                            for j in 0..child.child_count() {
                                if let Some(inner) = child.child(j) {
                                    if stmt_modifies_var(&inner, var_name, source) {
                                        return true;
                                    }
                                }
                            }
                        }
                        "compound_statement" => {}
                        // Single-statement bodies (no braces): check directly
                        "expression_statement" | "declaration"
                            if stmt_modifies_var(&child, var_name, source) =>
                        {
                            return true;
                        }
                        "expression_statement" | "declaration" => {}
                        // Nested control flow (else-if chains, etc.)
                        "if_statement" | "while_statement" | "for_statement" | "do_statement"
                        | "switch_statement"
                            if stmt_modifies_var(&child, var_name, source) =>
                        {
                            return true;
                        }
                        "if_statement" | "while_statement" | "for_statement" | "do_statement"
                        | "switch_statement" => {}
                        // switch case labels and goto targets
                        "case_statement" | "default_statement" | "labeled_statement" => {
                            for j in 0..child.child_count() {
                                if let Some(inner) = child.child(j) {
                                    if stmt_modifies_var(&inner, var_name, source) {
                                        return true;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        _ => {}
    }
    false
}

/// Returns true if the compound_statement has a direct-child declaration of `var_name`,
/// meaning any assignments to `var_name` within it target an inner-scope shadow variable.
fn compound_declares_var(compound: &Node, var_name: &str, source: &str) -> bool {
    for i in 0..compound.child_count() {
        if let Some(stmt) = compound.child(i) {
            if stmt.kind() == "declaration" {
                for j in 0..stmt.child_count() {
                    if let Some(child) = stmt.child(j) {
                        if child.kind() == "init_declarator" {
                            if let Some(decl) = child.child_by_field_name("declarator") {
                                if extract_leaf_identifier(&decl, source) == var_name {
                                    return true;
                                }
                            }
                        } else if child.kind() == "identifier" {
                            if child.utf8_text(source.as_bytes()).unwrap_or("") == var_name {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

/// Check if a call expression passes `&var_name` as an argument.
fn call_takes_address_of(call: &Node, var_name: &str, source: &str) -> bool {
    if let Some(args) = call.child_by_field_name("arguments") {
        for i in 0..args.child_count() {
            if let Some(arg) = args.child(i) {
                // Match &var_name (unary_expression with & operator)
                if arg.kind() == "pointer_expression" || arg.kind() == "unary_expression" {
                    let text = arg.utf8_text(source.as_bytes()).unwrap_or("");
                    if text == format!("&{}", var_name) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Extract leaf identifier from a declarator chain (pointer_declarator → identifier).
fn extract_leaf_identifier(node: &Node, source: &str) -> String {
    match node.kind() {
        "identifier" => node.utf8_text(source.as_bytes()).unwrap_or("").to_string(),
        "pointer_declarator" | "array_declarator" => {
            if let Some(inner) = node.child_by_field_name("declarator") {
                extract_leaf_identifier(&inner, source)
            } else {
                String::new()
            }
        }
        _ => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "identifier" {
                        return child.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                    }
                }
            }
            String::new()
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience functions for rule integration
// ---------------------------------------------------------------------------

/// Returns true if the expression provably fits in a signed integer of the given bit width.
/// Combines macro constants, loop-bound extraction, and local variable resolution.
///
/// For left shift operations, also verifies the left operand is non-negative
/// (shifting negative values is UB in C regardless of result).
pub fn expression_fits_in_signed(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    bits: u32,
) -> bool {
    let loop_ranges = extract_loop_var_ranges(node, source, macros);
    let mut var_ranges = loop_ranges.clone();
    resolve_identifiers_in_expr(node, source, macros, &loop_ranges, &mut var_ranges);

    if let Some(range) = try_evaluate_range(node, source, macros, &var_ranges) {
        // For left shift: shifting negative values is UB even if result fits
        if node.kind() == "binary_expression" {
            if is_shift_operator(node, source) && range.min < 0 {
                return false;
            }
            // Also check if left operand of shift is negative
            if is_shift_operator(node, source) {
                if let Some(left) = node.child_by_field_name("left") {
                    if let Some(lr) = try_evaluate_range(&left, source, macros, &var_ranges) {
                        if lr.min < 0 {
                            return false;
                        }
                    }
                }
            }
        }
        return range.fits_in_signed(bits);
    }
    false
}

/// Returns true if the expression provably fits in an unsigned integer of the given bit width.
pub fn expression_fits_in_unsigned(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    bits: u32,
) -> bool {
    let loop_ranges = extract_loop_var_ranges(node, source, macros);
    let mut var_ranges = loop_ranges.clone();
    resolve_identifiers_in_expr(node, source, macros, &loop_ranges, &mut var_ranges);

    if let Some(range) = try_evaluate_range(node, source, macros, &var_ranges) {
        return range.fits_in_unsigned(bits);
    }
    false
}

/// VRA-backed version of `expression_fits_in_signed`.
/// Tries CFG-based value-range analysis first, falls back to syntactic analysis.
pub fn expression_fits_in_signed_vra(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    bits: u32,
    vra_var_ranges: Option<&VarRangeMap>,
) -> bool {
    // Try VRA-provided ranges first
    if let Some(var_ranges) = vra_var_ranges {
        if let Some(range) = try_evaluate_range(node, source, macros, var_ranges) {
            // For left shift: shifting negative values is UB even if result fits
            if node.kind() == "binary_expression" && is_shift_operator(node, source) {
                if range.min < 0 {
                    return false;
                }
                if let Some(left) = node.child_by_field_name("left") {
                    if let Some(lr) = try_evaluate_range(&left, source, macros, var_ranges) {
                        if lr.min < 0 {
                            return false;
                        }
                    }
                }
            }
            return range.fits_in_signed(bits);
        }
    }
    // Fallback to syntactic analysis
    expression_fits_in_signed(node, source, macros, bits)
}

/// Returns true only when the expression *definitely* overflows the signed
/// bound — i.e. its entire computed value range lies outside the representable
/// band (every value overflows), such as `INT_MAX + 1` → `[INT_MAX+1,
/// INT_MAX+1]` or `SHRT_MAX + 1` (width-sensitive).
///
/// This is deliberately stronger than `!expression_fits_in_signed_vra`: a range
/// that merely *straddles* the bound (e.g. a parameter VRA-defaulted to the full
/// type range `[INT_MIN, INT_MAX]`, whose `+1` is `[INT_MIN+1, INT_MAX+1]`) is a
/// *possible*, not definite, overflow and returns false. The INT32-C provenance
/// gate uses this so constant-MAX overflows still fire while operands with
/// unknown-but-practically-bounded ranges stay suppressed. Returns false
/// whenever the range cannot be computed.
pub fn expression_overflows_signed_vra(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    bits: u32,
    vra_var_ranges: Option<&VarRangeMap>,
) -> bool {
    if bits == 0 || bits > 63 {
        return false;
    }
    if let Some(var_ranges) = vra_var_ranges {
        if let Some(range) = try_evaluate_range(node, source, macros, var_ranges) {
            let signed_max = (1i64 << (bits - 1)) - 1;
            let signed_min = -(1i64 << (bits - 1));
            // Definite overflow: the whole range is above max or below min.
            return range.min > signed_max || range.max < signed_min;
        }
    }
    false
}

/// Unsigned analogue of [`expression_overflows_signed_vra`]: returns true only
/// when the expression *definitely* wraps an unsigned `bits`-wide type — its
/// entire computed range lies above the unsigned max (e.g. `UINT_MAX + 1`) or
/// entirely below zero (a definite underflow/wrap such as `0u - 1`). A range
/// that merely straddles a bound (an unknown-but-bounded operand) is a
/// *possible*, not definite, wrap and returns false, so bounded unsigned
/// counters stay suppressed. Returns false whenever the range cannot be
/// computed.
pub fn expression_overflows_unsigned_vra(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    bits: u32,
    vra_var_ranges: Option<&VarRangeMap>,
) -> bool {
    if bits == 0 || bits > 63 {
        return false;
    }
    if let Some(var_ranges) = vra_var_ranges {
        if let Some(range) = try_evaluate_range(node, source, macros, var_ranges) {
            let unsigned_max = (1i64 << bits) - 1;
            return range.min > unsigned_max || range.max < 0;
        }
    }
    false
}

/// VRA-backed version of `expression_fits_in_unsigned`.
/// Tries CFG-based value-range analysis first, falls back to syntactic analysis.
pub fn expression_fits_in_unsigned_vra(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    bits: u32,
    vra_var_ranges: Option<&VarRangeMap>,
) -> bool {
    // Try VRA-provided ranges first.
    // VRA is used only to PROVE SAFETY (suppress): if VRA says the result fits,
    // return true immediately. If VRA says overflow is possible, fall through to
    // syntactic analysis — VRA's loop widening can be over-conservative (e.g.
    // widening data to UINT_MAX after `data=2` in a bounded loop), and the
    // syntactic path has separate constant-propagation that handles those cases.
    if let Some(var_ranges) = vra_var_ranges {
        if let Some(range) = try_evaluate_range(node, source, macros, var_ranges) {
            if range.fits_in_unsigned(bits) {
                return true;
            }
        }
    }
    // Fallback to syntactic analysis
    expression_fits_in_unsigned(node, source, macros, bits)
}

/// Resolve identifiers in an expression by scanning local assignments.
pub fn resolve_identifiers_in_expr(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    loop_ranges: &VarRangeMap,
    var_ranges: &mut VarRangeMap,
) {
    if node.kind() == "identifier" {
        let name = node.utf8_text(source.as_bytes()).unwrap_or("");
        if !name.is_empty() && !macros.contains_key(name) && !var_ranges.contains_key(name) {
            if let Some(range) = resolve_local_var_range(name, node, source, macros, loop_ranges) {
                var_ranges.insert(name.to_string(), range);
            }
        }
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            resolve_identifiers_in_expr(&child, source, macros, loop_ranges, var_ranges);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_shift_operator(node: &Node, source: &str) -> bool {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "<<" || child.kind() == ">>" {
                return true;
            }
            // Also check text content for operator nodes
            if let Ok(text) = child.utf8_text(source.as_bytes()) {
                if text == "<<" || text == ">>" {
                    return true;
                }
            }
        }
    }
    false
}

fn get_operator_text(node: &Node, source: &str) -> String {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            let kind = child.kind();
            if matches!(
                kind,
                "<" | "<="
                    | ">"
                    | ">="
                    | "=="
                    | "!="
                    | "+"
                    | "-"
                    | "*"
                    | "/"
                    | "<<"
                    | ">>"
                    | "&&"
                    | "||"
            ) {
                return child.utf8_text(source.as_bytes()).unwrap_or("").to_string();
            }
        }
    }
    String::new()
}

/// Parse a C char literal like `' '`, `'a'`, `'\n'`, `'\0'`, `'\x41'` into its integer value.
fn parse_char_literal(text: &str) -> Option<u8> {
    // Expect surrounding single quotes, possibly with L/u/U prefix
    let inner = text.strip_prefix('\'').or_else(|| {
        text.strip_prefix("L'")
            .or_else(|| text.strip_prefix("u'"))
            .or_else(|| text.strip_prefix("U'"))
    })?;
    let inner = inner.strip_suffix('\'')?;

    if let Some(escaped) = inner.strip_prefix('\\') {
        match escaped.as_bytes().first()? {
            b'n' => Some(b'\n'),
            b't' => Some(b'\t'),
            b'r' => Some(b'\r'),
            b'0' if escaped.len() == 1 => Some(0),
            b'\\' => Some(b'\\'),
            b'\'' => Some(b'\''),
            b'"' => Some(b'"'),
            b'a' => Some(7),
            b'b' => Some(8),
            b'f' => Some(12),
            b'v' => Some(11),
            b'x' => u8::from_str_radix(&escaped[1..], 16).ok(),
            d if d.is_ascii_digit() => u8::from_str_radix(escaped, 8).ok(),
            _ => None,
        }
    } else {
        let ch = inner.chars().next()?;
        if ch.is_ascii() {
            Some(ch as u8)
        } else {
            None
        }
    }
}

fn parse_integer_literal(text: &str) -> Option<i64> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    // Handle negative literals
    if let Some(rest) = text.strip_prefix('-') {
        let val = parse_unsigned_literal(rest.trim())?;
        return val.checked_neg();
    }
    parse_unsigned_literal(text)
}

fn parse_unsigned_literal(text: &str) -> Option<i64> {
    let text = strip_integer_suffix(text);
    if text.starts_with("0x") || text.starts_with("0X") {
        i64::from_str_radix(&text[2..], 16).ok()
    } else if text.starts_with("0b") || text.starts_with("0B") {
        i64::from_str_radix(&text[2..], 2).ok()
    } else if text.starts_with('0') && text.len() > 1 && text.chars().all(|c| c.is_ascii_digit()) {
        i64::from_str_radix(&text[1..], 8).ok()
    } else {
        text.parse::<i64>().ok()
    }
}

fn strip_integer_suffix(text: &str) -> &str {
    // Strip trailing: ULL, ull, UL, ul, LL, ll, U, u, L, l
    let suffixes = [
        "ULL", "ull", "Ull", "uLL", "UL", "ul", "Ul", "uL", "LL", "ll", "U", "u", "L", "l",
    ];
    for suffix in &suffixes {
        if let Some(stripped) = text.strip_suffix(suffix) {
            return stripped;
        }
    }
    text
}

fn is_c_identifier(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
        && text.chars().all(|c| c.is_alphanumeric() || c == '_')
}

fn parens_balanced(text: &str) -> bool {
    let mut depth = 0i32;
    for ch in text.chars() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_integer_literal() {
        assert_eq!(parse_integer_literal("42"), Some(42));
        assert_eq!(parse_integer_literal("0xFF"), Some(255));
        assert_eq!(parse_integer_literal("0x1F"), Some(31));
        assert_eq!(parse_integer_literal("010"), Some(8));
        assert_eq!(parse_integer_literal("0"), Some(0));
        assert_eq!(parse_integer_literal("-1"), Some(-1));
        assert_eq!(parse_integer_literal("50UL"), Some(50));
        assert_eq!(parse_integer_literal("1000LL"), Some(1000));
    }

    #[test]
    fn test_try_evaluate_text_simple() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("42", &macros), Some(42));
        assert_eq!(try_evaluate_text("(42)", &macros), Some(42));
        assert_eq!(try_evaluate_text("50 * 1000", &macros), Some(50000));
        assert_eq!(try_evaluate_text("250 * 1000", &macros), Some(250000));
    }

    #[test]
    fn test_try_evaluate_text_with_macros() {
        let mut macros = MacroConstantMap::new();
        macros.insert("DELAY_MS".to_string(), 50);
        assert_eq!(try_evaluate_text("DELAY_MS", &macros), Some(50));
        assert_eq!(try_evaluate_text("DELAY_MS * 1000", &macros), Some(50000));
        assert_eq!(try_evaluate_text("(DELAY_MS * 1000)", &macros), Some(50000));
    }

    #[test]
    fn test_try_evaluate_text_shift() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("1 << 4", &macros), Some(16));
        assert_eq!(try_evaluate_text("500 * (1 << 1)", &macros), Some(1000));
    }

    #[test]
    fn test_collect_macro_constants_chained() {
        let mut macros = MacroConstantMap::new();
        macros.insert("A".to_string(), 10);
        // Simulates A * 5 where A=10
        assert_eq!(try_evaluate_text("A * 5", &macros), Some(50));
    }

    #[test]
    fn test_value_range_fits() {
        let r = ValueRange::new(0, 50000);
        assert!(r.fits_in_signed(32)); // [-2^31, 2^31-1] easily fits 50000
        assert!(r.fits_in_unsigned(16)); // [0, 65535] fits 50000
        assert!(!r.fits_in_unsigned(15)); // [0, 32767] doesn't fit 50000

        let r2 = ValueRange::new(-100, 100);
        assert!(r2.fits_in_signed(8)); // [-128, 127]
        assert!(!r2.fits_in_unsigned(8)); // negative min
    }

    #[test]
    fn test_value_range_mul() {
        let a = ValueRange::new(0, 50);
        let b = ValueRange::exact(1000);
        let result = a.mul(&b).unwrap();
        assert_eq!(result.min, 0);
        assert_eq!(result.max, 50000);
        assert!(result.fits_in_signed(32));
    }

    #[test]
    fn test_value_range_shl() {
        let a = ValueRange::exact(500);
        let b = ValueRange::new(0, 1);
        let result = a.shl(&b).unwrap();
        assert_eq!(result.min, 500);
        assert_eq!(result.max, 1000);
        assert!(result.fits_in_signed(32));
    }

    // --- New tests for uncovered branches ---

    #[test]
    fn test_try_evaluate_text_addition_subtraction() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("10 + 20", &macros), Some(30));
        assert_eq!(try_evaluate_text("100 - 37", &macros), Some(63));
        assert_eq!(try_evaluate_text("5 + 3 + 2", &macros), Some(10));
    }

    #[test]
    fn test_try_evaluate_text_division() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("100 / 5", &macros), Some(20));
        assert_eq!(try_evaluate_text("100 / 0", &macros), None); // div by zero
        assert_eq!(try_evaluate_text("7 / 2", &macros), Some(3)); // truncation
    }

    #[test]
    fn test_try_evaluate_text_right_shift() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("256 >> 4", &macros), Some(16));
        assert_eq!(try_evaluate_text("1 >> 0", &macros), Some(1));
    }

    #[test]
    fn test_try_evaluate_text_precedence() {
        let macros = MacroConstantMap::new();
        // * has higher precedence than +
        assert_eq!(try_evaluate_text("2 + 3 * 4", &macros), Some(14));
        // parens override
        assert_eq!(try_evaluate_text("(2 + 3) * 4", &macros), Some(20));
    }

    #[test]
    fn test_try_evaluate_text_arrow_not_minus() {
        let macros = MacroConstantMap::new();
        // "a->b" should not parse as subtraction; returns None (not a constant)
        assert_eq!(try_evaluate_text("a->b", &macros), None);
    }

    #[test]
    fn test_try_evaluate_text_builtin_macros() {
        let macros = BUILTIN_LIMIT_MACROS.clone();
        assert_eq!(try_evaluate_text("INT_MAX", &macros), Some(2147483647));
        assert_eq!(try_evaluate_text("CHAR_BIT", &macros), Some(8));
        assert_eq!(try_evaluate_text("INT_MAX + 1", &macros), Some(2147483648));
    }

    #[test]
    fn test_try_evaluate_text_nested_parens() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("(10)", &macros), Some(10));
        assert_eq!(try_evaluate_text("(2 + 3) * (4 + 1)", &macros), Some(25));
        assert_eq!(try_evaluate_text("((10))", &macros), Some(10));
        assert_eq!(try_evaluate_text("((2 + 3) * (4 + 1))", &macros), Some(25));
    }

    #[test]
    fn test_parse_integer_literal_binary() {
        assert_eq!(parse_integer_literal("0b1010"), Some(10));
        assert_eq!(parse_integer_literal("0B11"), Some(3));
    }

    #[test]
    fn test_parse_integer_literal_edge_cases() {
        assert_eq!(parse_integer_literal(""), None);
        assert_eq!(parse_integer_literal("0xFFFFFFFF"), Some(4294967295));
        assert_eq!(parse_integer_literal("100ULL"), Some(100));
    }

    #[test]
    fn test_is_c_identifier() {
        assert!(is_c_identifier("foo"));
        assert!(is_c_identifier("_bar"));
        assert!(is_c_identifier("baz123"));
        assert!(!is_c_identifier(""));
        assert!(!is_c_identifier("123abc"));
        assert!(!is_c_identifier("a-b"));
    }

    #[test]
    fn test_parens_balanced() {
        assert!(parens_balanced("()"));
        assert!(parens_balanced("(a + (b * c))"));
        assert!(parens_balanced("no_parens"));
        assert!(!parens_balanced("("));
        assert!(!parens_balanced(")"));
        assert!(!parens_balanced(")("));
        assert!(!parens_balanced("((())"));
    }

    #[test]
    fn test_value_range_add() {
        let a = ValueRange::new(10, 20);
        let b = ValueRange::new(5, 15);
        let result = a.add(&b).unwrap();
        assert_eq!(result.min, 15);
        assert_eq!(result.max, 35);
    }

    #[test]
    fn test_value_range_sub() {
        let a = ValueRange::new(10, 20);
        let b = ValueRange::new(5, 15);
        let result = a.sub(&b).unwrap();
        assert_eq!(result.min, -5); // 10 - 15
        assert_eq!(result.max, 15); // 20 - 5
    }

    #[test]
    fn test_value_range_fits_edge_cases() {
        // 0-bit width
        assert!(!ValueRange::exact(0).fits_in_signed(0));
        assert!(!ValueRange::exact(0).fits_in_unsigned(0));

        // 64-bit always fits for signed
        assert!(ValueRange::new(i64::MIN, i64::MAX).fits_in_signed(64));

        // 64-bit unsigned
        assert!(ValueRange::new(0, i64::MAX).fits_in_unsigned(64));
        assert!(!ValueRange::new(-1, 0).fits_in_unsigned(64));
    }

    #[test]
    fn test_value_range_shl_invalid_shift() {
        let a = ValueRange::exact(1);
        let b = ValueRange::new(0, 100); // max > 63
        assert!(a.shl(&b).is_none());
    }

    #[test]
    fn test_collect_macro_constants_from_ast() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "#define MY_CONST 42\n#define DOUBLE_CONST (MY_CONST * 2)\nint x;\n";
        let tree = parser.parse(code, None).unwrap();
        let macros = collect_macro_constants(&tree.root_node(), code);
        assert_eq!(macros.get("MY_CONST"), Some(&42));
        assert_eq!(macros.get("DOUBLE_CONST"), Some(&84));
    }

    #[test]
    fn test_collect_macro_aliases_from_ast() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "#define SYSTEM system\n#define BUFSIZE 1024\nint x;\n";
        let tree = parser.parse(code, None).unwrap();
        let aliases = collect_macro_aliases(&tree.root_node(), code);
        assert_eq!(aliases.get("SYSTEM"), Some(&"system".to_string()));
        // BUFSIZE is numeric, should NOT be in aliases
        assert!(!aliases.contains_key("BUFSIZE"));
    }

    #[test]
    fn test_try_evaluate_expr_ast() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "int x = 10 + 20;\n";
        let tree = parser.parse(code, None).unwrap();
        let macros = MacroConstantMap::new();

        // Navigate to the binary expression: translation_unit > declaration > init_declarator > value
        let root = tree.root_node();
        let decl = root.child(0).unwrap();
        let init = decl.child_by_field_name("declarator").unwrap();
        if let Some(value) = init.child_by_field_name("value") {
            let result = try_evaluate_expr(&value, code, &macros);
            assert_eq!(result, Some(30));
        }
    }

    // --- Tests for sizeof resolution ---

    #[test]
    fn test_resolve_sizeof_type_basic() {
        assert_eq!(resolve_sizeof_type("char"), Some(1));
        assert_eq!(resolve_sizeof_type("unsigned char"), Some(1));
        assert_eq!(resolve_sizeof_type("int8_t"), Some(1));
        assert_eq!(resolve_sizeof_type("bool"), Some(1));
        assert_eq!(resolve_sizeof_type("_Bool"), Some(1));
        assert_eq!(resolve_sizeof_type("short"), Some(2));
        assert_eq!(resolve_sizeof_type("uint16_t"), Some(2));
        assert_eq!(resolve_sizeof_type("int"), Some(4));
        assert_eq!(resolve_sizeof_type("unsigned int"), Some(4));
        assert_eq!(resolve_sizeof_type("float"), Some(4));
        assert_eq!(resolve_sizeof_type("wchar_t"), Some(4));
        assert_eq!(resolve_sizeof_type("long"), Some(8));
        assert_eq!(resolve_sizeof_type("double"), Some(8));
        assert_eq!(resolve_sizeof_type("size_t"), Some(8));
        assert_eq!(resolve_sizeof_type("long double"), Some(16));
    }

    #[test]
    fn test_resolve_sizeof_type_pointers() {
        assert_eq!(resolve_sizeof_type("int *"), Some(8));
        assert_eq!(resolve_sizeof_type("char *"), Some(8));
        assert_eq!(resolve_sizeof_type("void *"), Some(8));
    }

    #[test]
    fn test_resolve_sizeof_type_unknown() {
        assert_eq!(resolve_sizeof_type("struct foo"), None);
        assert_eq!(resolve_sizeof_type("my_custom_type"), None);
    }

    #[test]
    fn test_resolve_sizeof_node_ast() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "int x = sizeof(int);\n";
        let tree = parser.parse(code, None).unwrap();
        let root = tree.root_node();
        let decl = root.child(0).unwrap();
        // Navigate to init_declarator → value (sizeof_expression)
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        let macros = MacroConstantMap::new();
                        let result = try_evaluate_expr(&value, code, &macros);
                        assert_eq!(result, Some(4), "sizeof(int) should be 4");
                    }
                }
            }
        }
    }

    // --- Tests for AST-based try_evaluate_expr branches ---

    #[test]
    fn test_try_evaluate_expr_unary() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "int x = -42;\n";
        let tree = parser.parse(code, None).unwrap();
        let macros = MacroConstantMap::new();
        let root = tree.root_node();
        let decl = root.child(0).unwrap();
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        assert_eq!(try_evaluate_expr(&value, code, &macros), Some(-42));
                    }
                }
            }
        }
    }

    #[test]
    fn test_try_evaluate_expr_cast() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "int x = (int)42;\n";
        let tree = parser.parse(code, None).unwrap();
        let macros = MacroConstantMap::new();
        let root = tree.root_node();
        let decl = root.child(0).unwrap();
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        assert_eq!(try_evaluate_expr(&value, code, &macros), Some(42));
                    }
                }
            }
        }
    }

    #[test]
    fn test_try_evaluate_expr_modulo() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "int x = 17 % 5;\n";
        let tree = parser.parse(code, None).unwrap();
        let macros = MacroConstantMap::new();
        let root = tree.root_node();
        let decl = root.child(0).unwrap();
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        assert_eq!(try_evaluate_expr(&value, code, &macros), Some(2));
                    }
                }
            }
        }
    }

    // --- Tests for try_evaluate_range ---

    #[test]
    fn test_try_evaluate_range_binary_ops() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "int x = a + 10;\n";
        let tree = parser.parse(code, None).unwrap();
        let macros = MacroConstantMap::new();
        let mut var_ranges = VarRangeMap::new();
        var_ranges.insert("a".to_string(), ValueRange::new(0, 50));

        let root = tree.root_node();
        let decl = root.child(0).unwrap();
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        let range = try_evaluate_range(&value, code, &macros, &var_ranges);
                        assert!(range.is_some());
                        let r = range.unwrap();
                        assert_eq!(r.min, 10);
                        assert_eq!(r.max, 60);
                    }
                }
            }
        }
    }

    #[test]
    fn test_try_evaluate_range_unary_neg() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "int x = -a;\n";
        let tree = parser.parse(code, None).unwrap();
        let macros = MacroConstantMap::new();
        let mut var_ranges = VarRangeMap::new();
        var_ranges.insert("a".to_string(), ValueRange::new(5, 10));

        let root = tree.root_node();
        let decl = root.child(0).unwrap();
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        let range = try_evaluate_range(&value, code, &macros, &var_ranges);
                        assert!(range.is_some());
                        let r = range.unwrap();
                        assert_eq!(r.min, -10);
                        assert_eq!(r.max, -5);
                    }
                }
            }
        }
    }

    // --- Tests for expression_fits_in_signed/unsigned ---

    #[test]
    fn test_expression_fits_in_signed_simple() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "int x = 100 + 200;\n";
        let tree = parser.parse(code, None).unwrap();
        let macros = MacroConstantMap::new();

        let root = tree.root_node();
        let decl = root.child(0).unwrap();
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        assert!(expression_fits_in_signed(&value, code, &macros, 16));
                        assert!(expression_fits_in_signed(&value, code, &macros, 32));
                    }
                }
            }
        }
    }

    #[test]
    fn test_expression_fits_in_unsigned_simple() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "int x = 100;\n";
        let tree = parser.parse(code, None).unwrap();
        let macros = MacroConstantMap::new();

        let root = tree.root_node();
        let decl = root.child(0).unwrap();
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        assert!(expression_fits_in_unsigned(&value, code, &macros, 8));
                        assert!(expression_fits_in_unsigned(&value, code, &macros, 16));
                    }
                }
            }
        }
    }

    // --- Tests for extract_loop_var_ranges ---

    #[test]
    fn test_extract_loop_var_ranges_for() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = r#"
void foo() {
    for (int i = 0; i < 10; i++) {
        int x = i;
    }
}
"#;
        let tree = parser.parse(code, None).unwrap();
        let macros = MacroConstantMap::new();

        // Navigate to the identifier "i" in "int x = i;"
        fn find_identifier<'a>(
            node: &tree_sitter::Node<'a>,
            name: &str,
            source: &str,
        ) -> Option<tree_sitter::Node<'a>> {
            if node.kind() == "identifier" && node.utf8_text(source.as_bytes()).ok() == Some(name) {
                // Check this is an rvalue usage (inside init_declarator value)
                if let Some(parent) = node.parent() {
                    if parent.kind() != "init_declarator"
                        || parent.child_by_field_name("value").map(|v| v.id()) == Some(node.id())
                    {
                        return Some(*node);
                    }
                }
            }
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if let Some(found) = find_identifier(&child, name, source) {
                        return Some(found);
                    }
                }
            }
            None
        }

        let root = tree.root_node();
        // Find the "i" in the assignment "int x = i"
        if let Some(i_node) = find_identifier(&root, "i", code) {
            let ranges = extract_loop_var_ranges(&i_node, code, &macros);
            if let Some(range) = ranges.get("i") {
                assert!(
                    range.max <= 9,
                    "i should be bounded to < 10, got max={}",
                    range.max
                );
            }
        }
    }

    // --- Tests for strip_integer_suffix ---

    #[test]
    fn test_strip_integer_suffix_cases() {
        assert_eq!(strip_integer_suffix("42ULL"), "42");
        assert_eq!(strip_integer_suffix("42ull"), "42");
        assert_eq!(strip_integer_suffix("42UL"), "42");
        assert_eq!(strip_integer_suffix("42ul"), "42");
        assert_eq!(strip_integer_suffix("42U"), "42");
        assert_eq!(strip_integer_suffix("42u"), "42");
        assert_eq!(strip_integer_suffix("42LL"), "42");
        assert_eq!(strip_integer_suffix("42ll"), "42");
        assert_eq!(strip_integer_suffix("42L"), "42");
        assert_eq!(strip_integer_suffix("42l"), "42");
        assert_eq!(strip_integer_suffix("42"), "42");
    }

    // --- Tests for try_evaluate_text edge cases ---

    #[test]
    fn test_try_evaluate_text_unary_negation() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("-5", &macros), Some(-5));
        assert_eq!(try_evaluate_text("-0", &macros), Some(0));
    }

    #[test]
    fn test_try_evaluate_text_comment_stripping() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("42 // comment", &macros), Some(42));
    }

    #[test]
    fn test_try_evaluate_text_suffixed_literal() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("42ULL", &macros), Some(42));
        assert_eq!(try_evaluate_text("100ul", &macros), Some(100));
    }

    #[test]
    fn test_try_evaluate_text_empty_and_whitespace() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("", &macros), None);
        assert_eq!(try_evaluate_text("  42  ", &macros), Some(42));
    }
}
