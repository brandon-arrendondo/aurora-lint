use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::analyze::macro_expand::{self, FunctionMacro};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Pre31C {
    /// Function-like macro definitions from the cross-file prescan
    /// (`ProjectContext::function_macros`) — needed because an unsafe
    /// macro's own `#define` usually lives in a header (curl's
    /// `DEBUGF`/`CURL_UNCONST` in `curl_setup.h`), not the file a call site
    /// sits in. A per-file-only `collect_function_macros` never saw those
    /// bodies, so every single-evaluation-safe macro defined outside the
    /// current file stayed (wrongly) flagged.
    function_macros: RefCell<HashMap<String, FunctionMacro>>,
}

impl Pre31C {
    pub fn new() -> Self {
        Self {
            function_macros: RefCell::new(HashMap::new()),
        }
    }
}

impl Default for Pre31C {
    fn default() -> Self {
        Self::new()
    }
}

impl CertRule for Pre31C {
    fn rule_id(&self) -> &'static str {
        "PRE31-C"
    }

    fn description(&self) -> &'static str {
        "Avoid side effects in arguments to unsafe macros"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "PRE31-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.function_macros.borrow_mut() = context.function_macros.clone();
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Real macro-body definitions (params + replacement text), collected the
        // same way every other macro-aware rule does (see
        // docs/design/internal-capability-catalog.md). Lets us prove a specific
        // parameter is evaluated at most once — the do-while(0)/passthrough
        // idiom that the old _Generic/statement-expression-only check missed —
        // instead of guessing from the definition's raw suffix text.
        //
        // Cross-file (prescan) definitions first, then this file's own
        // `collect_function_macros` layered on top so a same-file
        // `#define` wins over a stale/differently-`#ifdef`'d cross-file one
        // — the same "project-wide plus this file's own, per-file winning"
        // idiom `merged_macro_aliases` uses (see the capability catalog).
        let mut function_macros = self.function_macros.borrow().clone();
        function_macros.extend(macro_expand::collect_function_macros(node, source));
        self.check_node(node, source, &function_macros, violations);
    }
}

impl Pre31C {
    fn check_node(
        &self,
        node: &Node,
        source: &str,
        function_macros: &HashMap<String, FunctionMacro>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_macro_call(&call_node, source, function_macros, violations);
        }
    }

    fn check_macro_call(
        &self,
        node: &Node,
        source: &str,
        function_macros: &HashMap<String, FunctionMacro>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);

            // Check if this is a potentially unsafe macro
            if self.is_unsafe_macro(function_name) {
                // Skip if the macro is defined with a safe pattern (_Generic or statement expr)
                if self.is_safe_macro_definition(function_name, source) {
                    return;
                }

                let macro_def = function_macros.get(function_name);
                let args = self.get_function_arguments(node, source);

                // Check each argument for side effects
                for (i, arg) in args.iter().enumerate() {
                    // String literals have no side effects — skip them.
                    let trimmed = arg.trim();
                    if trimmed.starts_with('"') && trimmed.ends_with('"') {
                        continue;
                    }
                    // A macro provably evaluates *this* parameter at most once
                    // when its name appears 0 or 1 times (whole-token) in the
                    // macro's own replacement text — the single-evaluation
                    // passthrough / do-while(0)-wrapper idiom (e.g.
                    // `#define DEBUGF(x) x`), which is the majority shape of
                    // real-world "safe" macros and was previously only
                    // recognized via the narrower _Generic/statement-expr check.
                    // A parameter referenced twice (MAX/CLAMP-style) still
                    // counts >1 and stays flagged, matching CERT's intent.
                    //
                    // Guarded to bodies with no `&&`/`||`/`?:` at all: CERT's
                    // concern isn't only "evaluated more than once" but also
                    // "evaluated an unpredictable number of times" — a
                    // single textual occurrence sitting inside a short-circuit
                    // or ternary branch may run zero times on some calls, which
                    // is exactly as surprising to a caller as running twice
                    // (`IS_VALID_RANGE(x, low, high) = (x)>=(low) && (x)<=(high)`
                    // always evaluates `low` but only conditionally `high`).
                    if let Some(def) = macro_def {
                        if !body_has_conditional_evaluation(&def.body) {
                            if let Some(param) = def.params.get(i) {
                                if count_whole_ident_occurrences(&def.body, param) <= 1 {
                                    continue;
                                }
                            }
                        }
                    }
                    if self.has_side_effects(arg, node, source) {
                        let start_point = node.start_position();

                        let severity = if function_name == "assert" {
                            Severity::Medium // assert is disabled in release builds
                        } else {
                            Severity::High
                        };

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity,
                            message: format!(
                                "Unsafe macro '{}' called with side effect in argument {}: '{}'",
                                function_name,
                                i + 1,
                                arg
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Move side effects outside macro call or use inline function"
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    fn is_unsafe_macro(&self, function_name: &str) -> bool {
        // Fast path: safe prefix short-circuits all checks
        if function_name.starts_with("SAFE_") {
            return false;
        }

        // Check for known safe patterns (small set — use linear search)
        const SAFE_MACROS: &[&str] = &["SAFE_ABS", "SAFE_MAX", "SAFE_MIN"];
        if SAFE_MACROS.contains(&function_name) {
            return false;
        }

        // Known unsafe macros (used with linear search; this is called only when
        // is_unsafe_macro returns true in check_macro_call, which filters first)
        const UNSAFE_MACROS: &[&str] = &[
            "ABS",
            "abs",
            "MAX",
            "max",
            "MIN",
            "min",
            "assert",
            "getc",
            "putc",
            "getwc",
            "putwc",
            "SWAP",
            "swap",
            "CLAMP",
            "clamp",
            "NDEBUG",
            "DEBUG",
            "SAFE_FREE",
            "SAFE_DELETE",
            "IF_DEBUG",
            "WHEN",
            "UNLESS",
        ];

        UNSAFE_MACROS.contains(&function_name)
            || (function_name.chars().all(|c| c.is_uppercase() || c == '_')
                && function_name.len() > 2)
    }

    /// Check if the source contains a safe definition of the macro
    /// Safe definitions use _Generic or statement expressions
    fn is_safe_macro_definition(&self, function_name: &str, source: &str) -> bool {
        // Look for #define of this macro, word-boundary-anchored so e.g. "MIN"
        // doesn't false-match a "#define MIN_VALUE ..." definition.
        let Ok(re) = regex::Regex::new(&format!(
            r"(?m)^\s*#\s*define\s+{}\b",
            regex::escape(function_name)
        )) else {
            return false;
        };
        let Some(m) = re.find(source) else {
            return false;
        };
        // Get the rest of the line/definition
        let rest = &source[m.start()..];
        // Check for safe patterns
        // _Generic evaluates its controlling expression only once
        if rest.contains("_Generic") {
            return true;
        }
        // GNU statement expression: ({ ... }) ensures single evaluation
        if rest.contains("({") {
            return true;
        }
        false
    }

    /// Remove content inside string literals from an expression so that
    /// function-call patterns inside strings don't trigger false positives.
    /// e.g. `PR "mbedtls_ssl_write() timeout" PW` → `PR  PW`
    fn strip_string_literals(&self, text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let mut in_string = false;
        let mut escape_next = false;
        for ch in text.chars() {
            if escape_next {
                escape_next = false;
                continue;
            }
            if ch == '\\' && in_string {
                escape_next = true;
                continue;
            }
            if ch == '"' {
                in_string = !in_string;
                continue;
            }
            if !in_string {
                result.push(ch);
            }
        }
        result
    }

    fn has_side_effects(&self, arg: &str, context_node: &Node, source: &str) -> bool {
        // Strip string literal content to avoid false positive function-call detection
        // inside quoted text (e.g., NW_LOGE(PR "...func()..." PW, ...))
        let stripped = self.strip_string_literals(arg);
        let arg_check = stripped.as_str();

        // Check for various types of side effects in the argument

        // Direct side effect operators
        if arg_check.contains("++")
            || arg_check.contains("--")
            || arg_check.contains("+=")
            || arg_check.contains("-=")
            || arg_check.contains("*=")
            || arg_check.contains("/=")
            || arg_check.contains("%=")
            || arg_check.contains("&=")
            || arg_check.contains("|=")
            || arg_check.contains("^=")
            || arg_check.contains("<<=")
            || arg_check.contains(">>=")
        {
            return true;
        }

        // Assignment operator
        if self.contains_assignment(arg_check) {
            return true;
        }

        // Function calls that might have side effects
        if self.contains_function_call_with_side_effects(arg_check) {
            return true;
        }

        // Volatile access - check both direct keyword and via volatile variables in source
        if arg_check.contains("volatile") {
            return true;
        }
        // Check if any identifier in arg was declared as volatile in the source
        if self.is_volatile_variable_access(arg_check, source) {
            return true;
        }

        // I/O operations
        if self.contains_io_operations(arg_check) {
            return true;
        }

        // Check for more complex expressions using AST analysis
        if let Some(arg_node) = self.find_argument_node(context_node, arg, source) {
            return self.analyze_node_for_side_effects(&arg_node, source);
        }

        false
    }

    fn contains_assignment(&self, arg: &str) -> bool {
        // Look for assignment that's not part of a comparison
        let assignment_pos = arg.find('=');
        if let Some(pos) = assignment_pos {
            // Make sure it's not == or != or >= or <=
            let before = if pos > 0 {
                arg.chars().nth(pos - 1)
            } else {
                None
            };
            let after = arg.chars().nth(pos + 1);

            !matches!(
                (before, after),
                (Some('!' | '=' | '<' | '>'), _) | (_, Some('='))
            )
        } else {
            false
        }
    }

    fn contains_function_call_with_side_effects(&self, arg: &str) -> bool {
        // Known functions that have side effects
        let side_effect_functions = [
            "printf", "fprintf", "sprintf", "scanf", "fscanf", "sscanf", "malloc", "calloc",
            "realloc", "free", "fopen", "fclose", "fread", "fwrite", "fgetc", "fputc", "getchar",
            "putchar", "gets", "puts", "rand", "srand", "time", "exit", "abort", "system",
            // String functions that mutate a buffer or hold internal state.
            // NOTE: strlen/strcmp/strncmp are deliberately NOT here — they only
            // read their arguments and are listed as pure below instead.
            "strcpy", "strncpy", "strcat", "strncat", "strtok", "strtol", "strtoul", "strtod",
            "atoi", "atol", "atof", // Memory functions
            "memcpy", "memmove", "memset", "memcmp",
        ];

        for func in &side_effect_functions {
            if arg.contains(&format!("{}(", func)) {
                return true;
            }
        }

        // Also check for any function call pattern: identifier followed by (
        // This catches user-defined functions that might have side effects
        self.contains_any_function_call(arg)
    }

    fn contains_any_function_call(&self, arg: &str) -> bool {
        // Look for function call pattern: identifier(
        // But exclude known safe operations like type casts and pure functions
        let chars: Vec<char> = arg.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            // Look for open paren
            if chars[i] == '(' {
                // Look backwards for identifier
                let mut end = i;
                // Skip whitespace
                while end > 0 && chars[end - 1].is_whitespace() {
                    end -= 1;
                }
                // Check if there's an identifier before the paren
                let mut start = end;
                while start > 0 && (chars[start - 1].is_alphanumeric() || chars[start - 1] == '_') {
                    start -= 1;
                }
                if start < end {
                    let identifier: String = chars[start..end].iter().collect();
                    // Filter out known safe constructs (type casts, sizeof, etc.)
                    let safe_patterns = [
                        "int",
                        "char",
                        "float",
                        "double",
                        "long",
                        "short",
                        "unsigned",
                        "signed",
                        "void",
                        "size_t",
                        "sizeof",
                        "typeof",
                        "__typeof__",
                    ];
                    // Pure functions that have no side effects (PRE31-C-EX1)
                    // These functions only compute a value from their inputs
                    let pure_functions = [
                        "strlen",
                        "strcmp",
                        "strncmp",
                        "abs",
                        "labs",
                        "llabs",
                        "fabs",
                        "fabsf",
                        "fabsl",
                        "sqrt",
                        "sqrtf",
                        "sqrtl",
                        "cbrt",
                        "cbrtf",
                        "cbrtl",
                        "sin",
                        "cos",
                        "tan",
                        "asin",
                        "acos",
                        "atan",
                        "atan2",
                        "sinh",
                        "cosh",
                        "tanh",
                        "asinh",
                        "acosh",
                        "atanh",
                        "exp",
                        "exp2",
                        "expm1",
                        "log",
                        "log2",
                        "log10",
                        "log1p",
                        "pow",
                        "hypot",
                        "ceil",
                        "floor",
                        "round",
                        "trunc",
                        "fmod",
                        "remainder",
                        "fmax",
                        "fmin",
                        "isnan",
                        "isinf",
                        "isfinite",
                        "isnormal",
                        "square", // Common user-defined pure function
                        "negate",
                        "negative",
                        "positive",
                    ];
                    if !safe_patterns.contains(&identifier.as_str())
                        && !identifier.starts_with("_Generic")
                        && !pure_functions.contains(&identifier.as_str())
                    {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn contains_io_operations(&self, arg: &str) -> bool {
        // Look for I/O related operations
        arg.contains("printf")
            || arg.contains("scanf")
            || arg.contains("getc")
            || arg.contains("putc")
            || arg.contains("fread")
            || arg.contains("fwrite")
            || arg.contains("cout")
            || arg.contains("cin") // C++ style I/O
    }

    fn find_argument_node<'a>(
        &self,
        call_node: &'a Node<'a>,
        arg_text: &str,
        source: &str,
    ) -> Option<Node<'a>> {
        // Try to find the AST node corresponding to this argument. Only named
        // nodes are real argument expressions — the `argument_list`'s own
        // literal `(`/`)`/`,` tokens are anonymous children and must be
        // skipped, not just `,` (an unfiltered `(`/`)` would otherwise count
        // as a spurious extra "argument", shifting every real argument's
        // index by one — see `get_function_arguments`).
        if let Some(arguments) = call_node.child_by_field_name("arguments") {
            for i in 0..arguments.child_count() {
                if let Some(child) = arguments.child(i) {
                    if child.is_named() {
                        let node_text = get_node_text(&child, source);
                        if node_text.trim() == arg_text.trim() {
                            return Some(child);
                        }
                    }
                }
            }
        }
        None
    }

    fn analyze_node_for_side_effects(&self, node: &Node, source: &str) -> bool {
        match node.kind() {
            "update_expression" => true,     // ++, --
            "assignment_expression" => true, // =, +=, etc.
            "call_expression" => {
                // Check if it's a function call that might have side effects
                if let Some(func_node) = node.child_by_field_name("function") {
                    let func_name = get_node_text(&func_node, source);
                    self.contains_function_call_with_side_effects(func_name)
                } else {
                    false
                }
            }
            _ => {
                // Recursively check child nodes
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if self.analyze_node_for_side_effects(&child, source) {
                            return true;
                        }
                    }
                }
                false
            }
        }
    }

    fn get_function_arguments(&self, node: &Node, source: &str) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(arguments) = node.child_by_field_name("arguments") {
            for i in 0..arguments.child_count() {
                if let Some(child) = arguments.child(i) {
                    // Only named children are real argument expressions — the
                    // `argument_list`'s own literal `(`/`)` tokens are
                    // anonymous and were previously counted as spurious extra
                    // "arguments" alongside `,` (an off-by-one that shifted
                    // every real argument's reported index and broke
                    // positional macro-parameter lookups).
                    if child.is_named() {
                        let arg_text = get_node_text(&child, source).to_string();
                        args.push(arg_text.trim().to_string());
                    }
                }
            }
        }

        args
    }

    /// Check if the argument contains access to a volatile variable
    fn is_volatile_variable_access(&self, arg: &str, source: &str) -> bool {
        // Extract identifiers from the argument
        let identifiers = self.extract_identifiers(arg);

        // Look for "volatile [type] <id>" (or "<type> volatile <id>") with <id>
        // ending on a real identifier boundary — a plain `source.contains(...)`
        // substring check would (and did) match a short id like "i" inside an
        // unrelated declaration's own trailing text, e.g. "volatile int i" is a
        // substring of "volatile int in;".
        const PREFIXES: &[&str] = &[
            "volatile int ",
            "volatile unsigned ",
            "volatile char ",
            "volatile short ",
            "volatile long ",
            "int volatile ",
            "volatile ",
        ];
        for id in identifiers {
            for prefix in PREFIXES {
                if contains_ident_after(source, prefix, &id) {
                    return true;
                }
            }
        }
        false
    }

    /// Extract all identifiers from an expression
    fn extract_identifiers(&self, expr: &str) -> Vec<String> {
        let mut identifiers = Vec::new();
        let chars: Vec<char> = expr.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            // Look for start of identifier
            if chars[i].is_alphabetic() || chars[i] == '_' {
                let start = i;
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let id: String = chars[start..i].iter().collect();
                // Filter out keywords
                let keywords = [
                    "if", "else", "while", "for", "return", "int", "char", "void", "float",
                    "double", "long", "short", "unsigned", "signed", "const", "volatile", "static",
                    "extern", "sizeof",
                ];
                if !keywords.contains(&id.as_str()) {
                    identifiers.push(id);
                }
            } else {
                i += 1;
            }
        }
        identifiers
    }
}

/// Count occurrences of `ident` in `text` as a whole token (not a substring of
/// a longer identifier) — used to prove a macro parameter is evaluated at most
/// once from its own replacement text.
fn count_whole_ident_occurrences(text: &str, ident: &str) -> usize {
    let chars: Vec<char> = text.chars().collect();
    let id: Vec<char> = ident.chars().collect();
    let (n, m) = (chars.len(), id.len());
    if m == 0 {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    while i + m <= n {
        if chars[i..i + m] == id[..] {
            let prev_ok = i == 0 || !is_ident_char(chars[i - 1]);
            let next_ok = i + m >= n || !is_ident_char(chars[i + m]);
            if prev_ok && next_ok {
                count += 1;
            }
        }
        i += 1;
    }
    count
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// True if a macro's replacement text contains a short-circuit (`&&`/`||`) or
/// ternary (`?:`) operator anywhere — i.e. some part of the body is only
/// conditionally evaluated, so a bare occurrence count can't prove a
/// parameter always runs exactly once.
fn body_has_conditional_evaluation(body: &str) -> bool {
    body.contains("&&") || body.contains("||") || body.contains('?')
}

/// True if `source` contains `prefix` immediately followed by `id` ending on a
/// real identifier boundary (not a prefix of a longer identifier).
fn contains_ident_after(source: &str, prefix: &str, id: &str) -> bool {
    let needle = format!("{prefix}{id}");
    let mut search_start = 0;
    while let Some(rel) = source[search_start..].find(needle.as_str()) {
        let match_start = search_start + rel;
        let after = match_start + needle.len();
        let boundary_ok = source[after..]
            .chars()
            .next()
            .is_none_or(|c| !is_ident_char(c));
        if boundary_ok {
            return true;
        }
        search_start = match_start + 1;
        if search_start > source.len() {
            break;
        }
    }
    false
}
