//! Shared buffer-size analysis API.
//!
//! Buffer-size reasoning ("how many elements / bytes does this allocation
//! hold?") was historically duplicated across rules: ARR30-C carried an
//! AST-driven [`BufferInfo`]/[`BufferSize`] model plus a family of
//! size-expression parsers, while STR31-C re-implemented overlapping
//! malloc/calloc/alloca arithmetic with its own inline regex blocks. This
//! module is the single home for that machinery so future false-positive
//! work (tasks 143/144/145) builds on one API instead of accreting into the
//! individual rule files.
//!
//! The parsers here are pure functions over the textual argument of an
//! allocation call (e.g. the `"5 * sizeof(int)"` inside `malloc(...)`). They
//! make the same fixed-width assumptions ARR30-C always has (typical 64-bit
//! Linux: `int` = 4, pointer = 8, …); see [`extract_sizeof_value`].

/// Information about a buffer (array or dynamically allocated memory).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BufferInfo {
    /// The buffer's variable name.
    pub name: String,
    /// The buffer's size, in whatever form it could be determined.
    pub size: BufferSize,
    /// Textual element type (e.g. `"int"`).
    pub element_type: String,
    /// Line the buffer was declared/allocated on.
    pub allocation_line: usize,
    /// Raw allocation byte count (for byte-level comparisons).
    pub alloc_bytes: Option<usize>,
}

/// Represents the size of a buffer.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum BufferSize {
    /// `char arr[10]`
    Static(usize),
    /// `malloc(10 * sizeof(int))` — element count
    DynamicCalculated(usize),
    /// `malloc(size)` — variable expression
    Dynamic(String),
    /// VLA: `int arr[n]` — symbolic size
    Symbolic(String),
    /// Size could not be determined.
    Unknown,
}

/// Evaluate a two-operand `A op B` arithmetic expression where `op` is `+`
/// or `-`. Returns `None` for anything more complex (more than two operands,
/// multiplication, leading minus, non-numeric operands).
///
/// Mirrors ARR30-C's historical `evaluate_simple_arithmetic`.
pub fn evaluate_simple_arithmetic(expr: &str) -> Option<isize> {
    let expr = expr.trim();

    // Handle "A - B"
    if expr.contains('-') && !expr.starts_with('-') {
        let parts: Vec<&str> = expr.split('-').collect();
        if parts.len() == 2 {
            let a: isize = parts[0].trim().parse().ok()?;
            let b: isize = parts[1].trim().parse().ok()?;
            return Some(a - b);
        }
    }

    // Handle "A + B"
    if expr.contains('+') {
        let parts: Vec<&str> = expr.split('+').collect();
        if parts.len() == 2 {
            let a: isize = parts[0].trim().parse().ok()?;
            let b: isize = parts[1].trim().parse().ok()?;
            return Some(a + b);
        }
    }

    None
}

/// Extract a non-negative numeric value from a size sub-expression, tolerating
/// surrounding parentheses and simple `A + B`/`A - B` arithmetic.
pub fn extract_numeric_value(s: &str) -> Option<usize> {
    let trimmed = s.trim();
    // Strip outer parentheses: "(10+1)" → "10+1"
    let inner = if trimmed.starts_with('(') && trimmed.ends_with(')') {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };
    // Try direct parse first
    if let Ok(v) = inner.parse() {
        return Some(v);
    }
    // Try evaluating simple arithmetic (e.g., "10+1")
    let result = evaluate_simple_arithmetic(inner)?;
    if result >= 0 {
        Some(result as usize)
    } else {
        None
    }
}

/// Canonical `type name -> byte size` lookup for a single, already-extracted
/// C type name (e.g. `"int"`, `"unsigned long"`, `"int64_t"` — the trimmed
/// inner text of a `sizeof(TYPE)` expression, not the whole expression).
/// A trailing `*` (pointer type) always resolves to 8 regardless of the
/// pointee. Returns `None` for a type this table has no fixed-width answer
/// for (structs, unions, unrecognised typedefs — callers decide their own
/// fallback). Assumes a typical 64-bit Linux target throughout (`long` = 8,
/// pointer = 8, `int` = 4, ...).
///
/// This is the single home for a `type_name -> byte size` table that used
/// to be reimplemented independently by `extract_sizeof_value` (below),
/// ARR38-C's `sizeof_type`, and `size_analysis::find_element_size` — each
/// with slightly different coverage and, in ARR38-C's case, a benchmark-
/// specific `"twoIntsStruct" => 8` entry that has no place in a shared
/// primitive (task 511).
pub fn sizeof_type_bytes(type_name: &str) -> Option<usize> {
    let t = type_name.trim();
    if t.ends_with('*') {
        return Some(8);
    }
    match t {
        "int64_t" | "uint64_t" => Some(8),
        "int32_t" | "uint32_t" => Some(4),
        "int16_t" | "uint16_t" => Some(2),
        "int8_t" | "uint8_t" => Some(1),
        "size_t" => Some(8),
        "wchar_t" => Some(4),
        "long long" | "unsigned long long" | "signed long long" => Some(8),
        "long" | "unsigned long" | "signed long" => Some(8),
        "int" | "unsigned int" | "signed int" => Some(4),
        "char" | "unsigned char" | "signed char" => Some(1),
        "short" | "unsigned short" | "signed short" => Some(2),
        "float" => Some(4),
        "double" => Some(8),
        _ => None,
    }
}

/// Ordered so a longer/more-specific type name is checked before a shorter
/// substring it contains (e.g. `"int64_t"` before `"int"`) — needed only by
/// [`extract_sizeof_value`]'s whole-expression substring-scan fallback.
/// [`sizeof_type_bytes`]'s exact-match lookup has no such ordering hazard.
const TYPE_SIZE_SUBSTRING_ORDER: &[(&str, usize)] = &[
    ("int64_t", 8),
    ("uint64_t", 8),
    ("int32_t", 4),
    ("uint32_t", 4),
    ("int16_t", 2),
    ("uint16_t", 2),
    ("int8_t", 1),
    ("uint8_t", 1),
    ("size_t", 8),
    ("wchar_t", 4),
    ("long long", 8),
    ("long", 8),
    ("int", 4),
    ("char", 1),
    ("short", 2),
    ("float", 4),
    ("double", 8),
];

/// Resolve the byte size of a `sizeof(TYPE)` sub-expression using fixed-width
/// assumptions (typical 64-bit Linux). Returns `None` if `s` contains no
/// `sizeof`, and falls back to pointer size (8) for unrecognised types.
pub fn extract_sizeof_value(s: &str) -> Option<usize> {
    if !s.contains("sizeof") {
        return None;
    }

    // Preferred path: extract the exact type text between `sizeof(` and `)`
    // and resolve it via the canonical exact-match table.
    if let Some(after_sizeof) = s.split_once("sizeof(").map(|(_, rest)| rest) {
        if let Some(type_name) = after_sizeof.split(')').next() {
            if let Some(size) = sizeof_type_bytes(type_name) {
                return Some(size);
            }
        }
    }

    // Fallback: whole-expression substring scan, for `sizeof(...)` text the
    // exact-match extraction above didn't handle cleanly (e.g. unusual
    // whitespace around the parentheses).
    for (type_name, size) in TYPE_SIZE_SUBSTRING_ORDER {
        if s.contains(type_name) {
            return Some(*size);
        }
    }

    // Default to pointer size if we can't determine
    Some(8)
}

/// Allocation function names whose first (or count) argument gives an
/// element-count buffer size. Includes the Juliet `ALLOCA` macro alias.
pub const ALLOC_FUNCTIONS: &[&str] =
    &["malloc", "calloc", "realloc", "alloca", "_alloca", "ALLOCA"];

/// Resolve the element-count buffer size of an allocation call from its
/// callee name and raw argument text. `calloc(n, sz)` uses the first argument;
/// every other allocator uses the whole argument expression. Returns `None`
/// when the size is not a compile-time constant element count.
pub fn alloc_call_element_count(func_name: &str, args_text: &str) -> Option<usize> {
    // calloc(nmemb, size): the element count is the first argument.
    let size_expr = if func_name == "calloc" {
        args_text.split(',').next().unwrap_or(args_text)
    } else {
        args_text
    };
    match calculate_malloc_size(size_expr)? {
        BufferSize::Static(n) | BufferSize::DynamicCalculated(n) => Some(n),
        _ => None,
    }
}

/// Calculate the element-count size from a malloc/calloc/realloc argument
/// expression. For `N * sizeof(T)` this returns the element count `N`, not
/// the byte total (see [`calculate_alloc_bytes`] for bytes).
pub fn calculate_malloc_size(malloc_args: &str) -> Option<BufferSize> {
    let trimmed = malloc_args.trim();

    // Pattern 1: Simple number - malloc(100)
    if let Some(size) = extract_numeric_value(trimmed) {
        return Some(BufferSize::DynamicCalculated(size));
    }

    // Pattern 1.5: (A op B) * sizeof(TYPE) — a parenthesized two-operand
    // arithmetic expression immediately multiplied by a sizeof, e.g.
    // malloc((N*M) * sizeof(int)) or malloc((N+1) * sizeof(char)). Handled
    // before Pattern 2's naive split-on-first-'*', which mis-splits on the
    // operator INSIDE the parens when it is itself '*' (task 509) — this
    // pattern only fires where Pattern 2 would otherwise fall through to
    // `Dynamic` (the '+'/'-' cases already succeed via Pattern 2's
    // extract_numeric_value/evaluate_simple_arithmetic fallback), so it is
    // purely additive.
    if let Some(caps) = regex::Regex::new(r"^\(\s*(\d+)\s*([+*\-])\s*(\d+)\s*\)\s*\*\s*sizeof")
        .ok()
        .and_then(|re| re.captures(trimmed))
    {
        let a = caps[1].parse::<usize>().ok();
        let op = caps.get(2).map(|m| m.as_str());
        let b = caps.get(3).and_then(|m| m.as_str().parse::<usize>().ok());
        if let Some(n) = eval_arith(a, op, b) {
            return Some(BufferSize::DynamicCalculated(n));
        }
    }

    // Pattern 2: COUNT * sizeof(TYPE) - malloc(5 * sizeof(int))
    // Store the COUNT (number of elements), not the byte size
    if trimmed.contains('*') && trimmed.contains("sizeof") {
        // Split only on the first '*' to handle cases like "3 * sizeof(int*)"
        if let Some(mult_pos) = trimmed.find('*') {
            let left = trimmed[..mult_pos].trim();
            let right = trimmed[mult_pos + 1..].trim();

            if let Some(c) = extract_numeric_value(left) {
                // Store element count, not byte count
                return Some(BufferSize::DynamicCalculated(c));
            }
            // Reversed order: sizeof(TYPE) * COUNT - malloc(sizeof(int) * 5)
            // (task 513, same shape as task 509's nested-multiply extension)
            if left.contains("sizeof") {
                if let Some(c) = extract_numeric_value(right) {
                    return Some(BufferSize::DynamicCalculated(c));
                }
            }
            // Count is a variable (e.g., data*sizeof(char)) — size is unknown
            // Do NOT fall through to pattern 3 which would misinterpret
            // "data*sizeof(char)" as sizeof(char)=1
            return Some(BufferSize::Dynamic(trimmed.to_string()));
        }
    }

    // Pattern 3: Just sizeof(TYPE) - malloc(sizeof(struct foo))
    if let Some(sizeof_val) = extract_sizeof_value(trimmed) {
        return Some(BufferSize::DynamicCalculated(sizeof_val));
    }

    // Pattern 4: Variable expression
    Some(BufferSize::Dynamic(trimmed.to_string()))
}

/// Calculate the raw byte count of a malloc/realloc allocation expression.
/// Unlike [`calculate_malloc_size`], `N * sizeof(T)` yields `N * sizeof(T)`
/// bytes rather than the element count.
pub fn calculate_alloc_bytes(malloc_args: &str) -> Option<usize> {
    let trimmed = malloc_args.trim();

    // Pattern 1: Simple number - malloc(100) → 100 bytes
    if let Some(size) = extract_numeric_value(trimmed) {
        return Some(size);
    }

    // Pattern 2: COUNT * sizeof(TYPE) - malloc(5 * sizeof(int)) → 5 * 4 = 20 bytes
    if trimmed.contains('*') && trimmed.contains("sizeof") {
        if let Some(mult_pos) = trimmed.find('*') {
            let left = trimmed[..mult_pos].trim();
            let right = trimmed[mult_pos + 1..].trim();

            if let (Some(c), Some(s)) = (extract_numeric_value(left), extract_sizeof_value(right)) {
                return Some(c * s);
            }
            // Reversed order: sizeof(TYPE) * COUNT - malloc(sizeof(int) * 5)
            // (task 513, same shape as task 509's nested-multiply extension)
            if let (Some(s), Some(c)) = (extract_sizeof_value(left), extract_numeric_value(right)) {
                return Some(c * s);
            }
        }
    }

    // Pattern 3: Just sizeof(TYPE) - malloc(sizeof(struct foo))
    if let Some(sizeof_val) = extract_sizeof_value(trimmed) {
        return Some(sizeof_val);
    }

    None
}

/// Parse a simple size expression: a bare `"49"` or an `N-M` subtraction such
/// as `"50-1"` / `"100-1"`. Returns `None` for anything more complex.
/// Subtraction uses `checked_sub`, so an underflow (`"1-5"`) yields `None`.
pub fn parse_simple_size_expr(expr: &str) -> Option<usize> {
    let expr = expr.trim();
    if let Ok(n) = expr.parse::<usize>() {
        return Some(n);
    }
    // N-M pattern (use rfind to handle potential negative results)
    if let Some(pos) = expr.rfind('-') {
        if pos > 0 {
            let left = expr[..pos].trim();
            let right = expr[pos + 1..].trim();
            if let (Ok(l), Ok(r)) = (left.parse::<usize>(), right.parse::<usize>()) {
                return l.checked_sub(r);
            }
        }
    }
    None
}

/// Line range `(start_row, end_row)` of the `function_definition` enclosing
/// `node`, or `None` if `node` is not inside one. Used to scope textual
/// scans to a single function and avoid cross-function pollution (e.g. a
/// bad-section `memset` bleeding into good-section analysis).
pub fn enclosing_function_lines(node: &tree_sitter::Node) -> Option<(usize, usize)> {
    let mut current = node.parent();
    while let Some(n) = current {
        if n.kind() == "function_definition" {
            return Some((n.start_position().row, n.end_position().row));
        }
        current = n.parent();
    }
    None
}

/// Content length of a string buffer initialized by a `memset`/`wmemset`
/// fill immediately followed by an explicit null terminator, scoped to the
/// function enclosing `call_node` and to the lines before the call.
///
/// This is the *actual* string length written into `var_name`, which is more
/// precise than the buffer's declared capacity — the distinction that lets a
/// copy rule keep the bad-section overflow (fill length > destination) while
/// suppressing the good-section copy (fill length fits the destination).
///
/// Matches patterns like:
///   memset(var, 'A', 49);   var[49] = '\0';     → 49
///   wmemset(var, L'A', 49);  var[49] = L'\0';    → 49
///   memset(var, 'A', 50-1);  var[50-1] = '\0';   → 49
///
/// When several matching fills precede the call (control-flow variants), the
/// largest is returned (worst case).
pub fn memset_content_length(
    var_name: &str,
    source: &str,
    call_node: &tree_sitter::Node,
) -> Option<usize> {
    let (fn_start, fn_end) = enclosing_function_lines(call_node)?;
    let call_line = call_node.start_position().row;
    memset_content_length_in_range(
        var_name,
        source,
        fn_start,
        std::cmp::min(call_line, fn_end + 1),
    )
}

/// Like [`memset_content_length`], but scans an explicit `[start, end)` row
/// range instead of deriving one from a call site. Lets a caller resolve the
/// content length written into `var_name` by a DIFFERENT function than the
/// one performing the copy — a Juliet "source" relay function such as
/// `data = badSource(data)`, where `badSource` memsets its own parameter and
/// returns it, so the fill lives outside the copying function's own range.
pub fn memset_content_length_in_range(
    var_name: &str,
    source: &str,
    start: usize,
    end: usize,
) -> Option<usize> {
    let lines: Vec<&str> = source.lines().collect();
    let mut best_size: Option<usize> = None;

    for i in start..std::cmp::min(end, lines.len()) {
        let trimmed = lines[i].trim();

        // Find wmemset( or memset( call
        let call_start = if let Some(pos) = trimmed.find("wmemset(") {
            pos + "wmemset(".len()
        } else if let Some(pos) = trimmed.find("memset(") {
            pos + "memset(".len()
        } else {
            continue;
        };

        // Extract arguments between parens
        let after_call = &trimmed[call_start..];
        let close_paren = match after_call.rfind(')') {
            Some(p) => p,
            None => continue,
        };
        let args_str = &after_call[..close_paren];
        let parts: Vec<&str> = args_str.splitn(3, ',').collect();
        if parts.len() != 3 {
            continue;
        }

        // First arg must be exactly our variable name
        if parts[0].trim() != var_name {
            continue;
        }

        // Third arg is the fill count
        let size = match parse_simple_size_expr(parts[2].trim()) {
            Some(s) => s,
            None => continue,
        };

        // Verify null termination follows within next 3 lines
        let null_term_prefix = format!("{}[", var_name);
        let search_end = std::cmp::min(i + 4, lines.len());
        for next_line in lines[(i + 1)..search_end].iter().map(|l| l.trim()) {
            if next_line.contains(&null_term_prefix)
                && (next_line.contains("'\\0'") || next_line.contains("L'\\0'"))
            {
                // Keep the largest content size seen (conservative: if multiple
                // branches set different sizes, use the worst case)
                best_size = Some(match best_size {
                    Some(prev) => std::cmp::max(prev, size),
                    None => size,
                });
                break;
            }
        }
    }
    best_size
}

/// Resolve a simple pointer alias within an explicit `[start, end]` row
/// range: the target of the first `var_name = otherIdentifier;` assignment
/// found (optionally cast), skipping self-assignment, `NULL`, and numeric
/// literals. An arithmetic-offset or call-shaped RHS (`var - 8`,
/// `malloc(...)`) never matches — the pattern requires a bare identifier
/// immediately before the `;`.
pub fn resolve_bare_alias_in_range(
    var_name: &str,
    source: &str,
    start: usize,
    end: usize,
) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();
    let pattern = format!(
        r"\b{}\s*=\s*(?:\([^)]*\)\s*)?(\w+)\s*;",
        regex::escape(var_name)
    );
    let re = regex::Regex::new(&pattern).ok()?;
    let end = end.min(lines.len().saturating_sub(1));
    for line in &lines[start..=end] {
        if let Some(caps) = re.captures(line) {
            let target = &caps[1];
            if target == var_name || target == "NULL" || target == "0" {
                continue;
            }
            return Some(target.to_string());
        }
    }
    None
}

/// Element-count buffer size of the largest `malloc`/`calloc`/`realloc`/
/// `alloca`-family allocation directly assigned to `var_name` within an
/// explicit `[start, end]` row range (worst case across multiple assignments
/// — e.g. one per dead-code branch). Does not resolve aliases; pair with
/// [`resolve_bare_alias_in_range`] for `var_name = other; other = malloc(...)`.
pub fn resolve_alloc_assigned_in_range(
    var_name: &str,
    source: &str,
    start: usize,
    end: usize,
) -> Option<usize> {
    let lines: Vec<&str> = source.lines().collect();
    let pattern = format!(
        r"\b{}\s*=\s*(?:\([^)]*\)\s*)?({})\s*\(([^;]*)\)",
        regex::escape(var_name),
        ALLOC_FUNCTIONS.join("|")
    );
    let re = regex::Regex::new(&pattern).ok()?;
    let end = end.min(lines.len().saturating_sub(1));
    let mut best: Option<usize> = None;
    for line in &lines[start..=end] {
        let Some(caps) = re.captures(line) else {
            continue;
        };
        let Some(size) = alloc_call_element_count(&caps[1], &caps[2]) else {
            continue;
        };
        best = Some(best.map_or(size, |b: usize| b.max(size)));
    }
    best
}

/// True if `var_name` was assigned the result of `strlen()` (or `wcslen()`
/// when `wide` is set) anywhere within `lines[fn_start..=fn_end]` — i.e. a
/// second-order "this size variable is itself strlen-derived, so the
/// allocation it sizes is dynamically safe" check, as opposed to
/// [`resolve_alloc_assigned_in_range`]'s first-order "what did this
/// allocation call's own argument say" check.
pub fn resolves_to_strlen_call(
    var_name: &str,
    lines: &[&str],
    fn_start: usize,
    fn_end: usize,
    wide: bool,
) -> bool {
    let pattern = if wide {
        format!(r"\b{}\s*=\s*wcslen\s*\(", regex::escape(var_name))
    } else {
        format!(r"\b{}\s*=\s*(?:w?)strlen\s*\(", regex::escape(var_name))
    };
    let Ok(re) = regex::Regex::new(&pattern) else {
        return false;
    };
    if lines.is_empty() || fn_start >= lines.len() {
        return false;
    }
    let end = fn_end.min(lines.len().saturating_sub(1));
    if fn_start > end {
        return false;
    }
    lines[fn_start..=end].iter().any(|l| re.is_match(l))
}

/// Evaluate a parenthesised allocation-size arithmetic capture of the form
/// `(N op M)` (or a bare `N`), as produced by the malloc/alloca size regexes.
/// `op` is `Some("+"|"-"|"*")` with both operands present, or `None` for a
/// bare `N` (in which case `b` must also be `None`). All other shapes — a
/// missing left operand, an unrecognised operator, or an operator without a
/// right operand — yield `None`. Overflow saturates to `None` via the
/// `checked_*` operations.
pub fn eval_arith(a: Option<usize>, op: Option<&str>, b: Option<usize>) -> Option<usize> {
    match (a, op, b) {
        (Some(a), Some("+"), Some(b)) => a.checked_add(b),
        (Some(a), Some("-"), Some(b)) => a.checked_sub(b),
        (Some(a), Some("*"), Some(b)) => a.checked_mul(b),
        (Some(a), None, None) => Some(a),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_arithmetic_two_operands_only() {
        assert_eq!(evaluate_simple_arithmetic("10 + 1"), Some(11));
        assert_eq!(evaluate_simple_arithmetic("50 - 1"), Some(49));
        // Three operands and multiplication are out of scope.
        assert_eq!(evaluate_simple_arithmetic("1 + 2 + 3"), None);
        assert_eq!(evaluate_simple_arithmetic("5 * 4"), None);
    }

    #[test]
    fn numeric_value_strips_parens_and_evaluates() {
        assert_eq!(extract_numeric_value("100"), Some(100));
        assert_eq!(extract_numeric_value("(10+1)"), Some(11));
        // Negative results are rejected (the size domain is unsigned).
        assert_eq!(extract_numeric_value("1-5"), None);
    }

    #[test]
    fn sizeof_type_bytes_exact_match_canonical_table() {
        // task 511: single canonical table backing extract_sizeof_value,
        // ARR38-C's former sizeof_type, and size_analysis::find_element_size.
        assert_eq!(sizeof_type_bytes("int"), Some(4));
        assert_eq!(sizeof_type_bytes("unsigned int"), Some(4));
        assert_eq!(sizeof_type_bytes("char"), Some(1));
        assert_eq!(sizeof_type_bytes("long"), Some(8));
        assert_eq!(sizeof_type_bytes("unsigned long"), Some(8));
        assert_eq!(sizeof_type_bytes("int64_t"), Some(8));
        assert_eq!(sizeof_type_bytes("uint64_t"), Some(8));
        assert_eq!(sizeof_type_bytes("int8_t"), Some(1));
        assert_eq!(sizeof_type_bytes("size_t"), Some(8));
        assert_eq!(sizeof_type_bytes("wchar_t"), Some(4));
        assert_eq!(sizeof_type_bytes("float"), Some(4));
        assert_eq!(sizeof_type_bytes("double"), Some(8));
        // Pointer types always resolve to 8 regardless of pointee.
        assert_eq!(sizeof_type_bytes("int *"), Some(8));
        assert_eq!(sizeof_type_bytes("struct foo*"), Some(8));
        // Structs/unions/unrecognised typedefs (incl. the old Juliet-only
        // "twoIntsStruct" hack, deliberately not carried into this table).
        assert_eq!(sizeof_type_bytes("twoIntsStruct"), None);
        assert_eq!(sizeof_type_bytes("struct foo"), None);
    }

    #[test]
    fn sizeof_uses_fixedwidth_table_with_pointer_default() {
        assert_eq!(extract_sizeof_value("sizeof(int)"), Some(4));
        assert_eq!(extract_sizeof_value("sizeof(char)"), Some(1));
        assert_eq!(extract_sizeof_value("sizeof(wchar_t)"), Some(4));
        // Unknown type falls back to pointer size.
        assert_eq!(extract_sizeof_value("sizeof(struct foo)"), Some(8));
        // No sizeof at all → None (distinct from the size-8 fallback).
        assert_eq!(extract_sizeof_value("42"), None);
    }

    #[test]
    fn sizeof_stdint_widths_not_shadowed_by_int_substring() {
        // int64_t/uint64_t used to substring-match "int" (4 bytes) before
        // ever reaching "long" (8 bytes); same root cause affected every
        // other fixed-width stdint type against its containing base name.
        assert_eq!(extract_sizeof_value("sizeof(int64_t)"), Some(8));
        assert_eq!(extract_sizeof_value("sizeof(uint64_t)"), Some(8));
        assert_eq!(extract_sizeof_value("sizeof(int32_t)"), Some(4));
        assert_eq!(extract_sizeof_value("sizeof(uint32_t)"), Some(4));
        assert_eq!(extract_sizeof_value("sizeof(int16_t)"), Some(2));
        assert_eq!(extract_sizeof_value("sizeof(uint16_t)"), Some(2));
        assert_eq!(extract_sizeof_value("sizeof(int8_t)"), Some(1));
        assert_eq!(extract_sizeof_value("sizeof(uint8_t)"), Some(1));
        assert_eq!(extract_sizeof_value("sizeof(size_t)"), Some(8));
        assert_eq!(extract_sizeof_value("sizeof(long long)"), Some(8));
        assert_eq!(extract_sizeof_value("sizeof(unsigned long long)"), Some(8));
    }

    #[test]
    fn sizeof_pointer_types_are_eight_bytes_regardless_of_base_type() {
        // "int*"/"char*"/"wchar_t*" were dead table entries: the bare
        // "int"/"char"/"wchar_t" checks matched first and returned the
        // base type's size instead of the pointer size (task 516).
        assert_eq!(extract_sizeof_value("sizeof(int*)"), Some(8));
        assert_eq!(extract_sizeof_value("sizeof(char*)"), Some(8));
        assert_eq!(extract_sizeof_value("sizeof(wchar_t*)"), Some(8));
        assert_eq!(extract_sizeof_value("sizeof(void*)"), Some(8));
        assert_eq!(extract_sizeof_value("sizeof(struct foo*)"), Some(8));
    }

    #[test]
    fn malloc_size_returns_element_count_bytes_returns_total() {
        // N * sizeof(T): element count vs byte total diverge here.
        assert!(matches!(
            calculate_malloc_size("5 * sizeof(int)"),
            Some(BufferSize::DynamicCalculated(5))
        ));
        assert_eq!(calculate_alloc_bytes("5 * sizeof(int)"), Some(20));
        // Variable count → Dynamic, never misread as sizeof(char)=1.
        assert!(matches!(
            calculate_malloc_size("n * sizeof(char)"),
            Some(BufferSize::Dynamic(_))
        ));
    }

    #[test]
    fn malloc_size_handles_nested_paren_arith_before_sizeof() {
        // (N*M) * sizeof(T): the inner '*' used to break Pattern 2's naive
        // split-on-first-'*' (task 509) — now resolved via Pattern 1.5.
        assert!(matches!(
            calculate_malloc_size("(4*3) * sizeof(int)"),
            Some(BufferSize::DynamicCalculated(12))
        ));
        // (N+M) * sizeof(T) and (N-M) * sizeof(T) already worked via
        // Pattern 2's arithmetic fallback — confirm Pattern 1.5 doesn't
        // change their answer.
        assert!(matches!(
            calculate_malloc_size("(4+3) * sizeof(int)"),
            Some(BufferSize::DynamicCalculated(7))
        ));
        assert!(matches!(
            calculate_malloc_size("(10-2) * sizeof(char)"),
            Some(BufferSize::DynamicCalculated(8))
        ));
    }

    #[test]
    fn malloc_size_handles_reversed_sizeof_times_count_order() {
        // sizeof(T) * COUNT (task 513): calculate_malloc_size only tried
        // COUNT * sizeof(T) before; the reversed order used to fall through
        // to Dynamic even though COUNT is a plain number.
        assert!(matches!(
            calculate_malloc_size("sizeof(int) * 5"),
            Some(BufferSize::DynamicCalculated(5))
        ));
        assert_eq!(calculate_alloc_bytes("sizeof(int) * 5"), Some(20));
        // Reversed order with a variable count still falls back to Dynamic
        // for calculate_malloc_size (Pattern 2's explicit early return).
        assert!(matches!(
            calculate_malloc_size("sizeof(char) * n"),
            Some(BufferSize::Dynamic(_))
        ));
        // calculate_alloc_bytes has no such guard and falls through to
        // Pattern 3's whole-string sizeof lookup here — pre-existing
        // behavior, unchanged by this task, same as the forward order
        // ("n * sizeof(char)") already exhibited.
        assert_eq!(calculate_alloc_bytes("sizeof(char) * n"), Some(1));
    }

    #[test]
    fn eval_arith_matches_checked_semantics() {
        assert_eq!(eval_arith(Some(10), Some("+"), Some(1)), Some(11));
        assert_eq!(eval_arith(Some(10), Some("-"), Some(3)), Some(7));
        assert_eq!(eval_arith(Some(4), Some("*"), Some(3)), Some(12));
        // Bare N (no operator) passes through.
        assert_eq!(eval_arith(Some(8), None, None), Some(8));
        // Underflow/overflow and malformed shapes yield None.
        assert_eq!(eval_arith(Some(3), Some("-"), Some(5)), None);
        assert_eq!(eval_arith(Some(usize::MAX), Some("+"), Some(1)), None);
        assert_eq!(eval_arith(None, Some("+"), Some(1)), None);
        assert_eq!(eval_arith(Some(1), Some("/"), Some(1)), None);
    }
}
