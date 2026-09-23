//! DCL06-C: Use meaningful symbolic constants to represent literal values
//!
//! Magic numbers (literal values) obscure code intent and create maintenance risks.
//! Use named symbolic constants (enums, const, macros) instead of embedding literals.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! char buffer[256];
//! fgets(buffer, 256, stdin);  // Magic number repeated
//!
//! if (age >= 18) { ... }       // Unclear meaning
//! ```
//!
//! **Compliant:**
//! ```c
//! enum { BUFFER_SIZE = 256 };
//! char buffer[BUFFER_SIZE];
//! fgets(buffer, sizeof(buffer), stdin);
//!
//! enum { ADULT_AGE = 18 };
//! if (age >= ADULT_AGE) { ... }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Dcl06C;

/// Tracks literal occurrences for duplicate detection
#[derive(Debug, Clone)]
struct LiteralInfo {
    value: String,
    line: usize,
    column: usize,
    context: String,
}

impl CertRule for Dcl06C {
    fn rule_id(&self) -> &'static str {
        "DCL06-C"
    }

    fn description(&self) -> &'static str {
        "Use meaningful symbolic constants to represent literal values"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "DCL06-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Track literal occurrences to detect magic numbers
        let mut literal_occurrences: HashMap<String, Vec<LiteralInfo>> = HashMap::new();
        let mut array_sizes: Vec<LiteralInfo> = Vec::new();

        self.analyze_literals(node, source, &mut literal_occurrences, &mut array_sizes);

        // Check for sizeof usage on arrays
        let sizeof_arrays = self.find_sizeof_usages(node, source);

        // Check for magic numbers (single or repeated occurrences)
        for (literal_value, occurrences) in &literal_occurrences {
            // Skip common acceptable values
            if self.is_acceptable_literal(literal_value) {
                continue;
            }

            // Flag any occurrence of non-trivial literal
            let first = &occurrences[0];
            let message = if occurrences.len() >= 2 {
                format!(
                    "Magic number '{}' appears {} times. Consider using a symbolic constant.",
                    literal_value,
                    occurrences.len()
                )
            } else if literal_value.starts_with('"') {
                format!(
                    "String literal {} should use a symbolic constant.",
                    literal_value
                )
            } else {
                format!(
                    "Magic number '{}' should use a symbolic constant.",
                    literal_value
                )
            };

            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                message,
                severity: self.severity(),
                line: first.line,
                column: first.column,
                file_path: String::new(),
                suggestion: Some(format!(
                    "Define a constant: enum {{ CONSTANT_NAME = {} }};",
                    literal_value
                )),
                requires_manual_review: None,
            });
        }

        // Check for magic numbers in array declarations
        // Only flag if sizeof() is not used on that array
        for array_size in &array_sizes {
            if !self.is_acceptable_literal(&array_size.value) {
                // context contains the array name
                let array_name = &array_size.context;

                // Don't flag if sizeof is used on this array
                if !array_name.is_empty() && sizeof_arrays.contains(array_name) {
                    continue;
                }

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    message: format!(
                        "Array size '{}' should use a symbolic constant instead of magic number.",
                        array_size.value
                    ),
                    severity: self.severity(),
                    line: array_size.line,
                    column: array_size.column,
                    file_path: String::new(),
                    suggestion: Some(format!(
                        "Define a constant: enum {{ ARRAY_SIZE = {} }};",
                        array_size.value
                    )),
                    requires_manual_review: None,
                });
            }
        }

        violations
    }
}

impl Dcl06C {
    /// Analyze AST for literal values
    fn analyze_literals(
        &self,
        node: &Node,
        source: &str,
        occurrences: &mut HashMap<String, Vec<LiteralInfo>>,
        array_sizes: &mut Vec<LiteralInfo>,
    ) {
        for n in query::find_descendants_of_kinds(*node, &["array_declarator", "number_literal"]) {
            match n.kind() {
                // Check for array declarator with numeric size
                "array_declarator" => {
                    if let Some(size_node) = self.find_array_size(&n) {
                        if size_node.kind() == "number_literal" {
                            let value = get_node_text(&size_node, source).to_string();
                            // Extract array name to check for sizeof usage
                            let array_name = self.extract_array_name(&n, source);
                            array_sizes.push(LiteralInfo {
                                value,
                                line: size_node.start_position().row + 1,
                                column: size_node.start_position().column + 1,
                                context: array_name.unwrap_or_default(),
                            });
                        }
                    }
                }
                // Track number literals in various contexts
                "number_literal" => {
                    let value = get_node_text(&n, source).to_string();

                    // Determine context
                    let context = self.get_literal_context(&n);
                    let operator = self.get_binary_operator(&n, source);

                    // Only track literals in suspicious contexts
                    if self.is_suspicious_context(&context)
                        && !self.is_well_known_idiom(&value, &operator)
                        && !self.value_echoed_in_sibling_identifier(&n, source)
                        && !self.is_version_macro_comparison(&n, source)
                        && !self.is_consistency_assert_operand(&n, source)
                    {
                        let info = LiteralInfo {
                            value: value.clone(),
                            line: n.start_position().row + 1,
                            column: n.start_position().column + 1,
                            context,
                        };

                        occurrences.entry(value).or_default().push(info);
                    }
                }
                _ => {}
            }
        }

        // Note: String literals are generally acceptable in context (error messages, etc.)
        // so we don't flag them to avoid false positives
    }

    /// Extract array name from array declarator. A struct member's
    /// declarator is a `field_identifier`, not an `identifier`, so
    /// `char name[64];` inside a struct had no name at all and could never
    /// be matched against a `sizeof(x.name)` (mechanism 7).
    fn extract_array_name(&self, array_decl: &Node, source: &str) -> Option<String> {
        for i in 0..array_decl.child_count() {
            if let Some(child) = array_decl.child(i) {
                if child.kind() == "identifier" || child.kind() == "field_identifier" {
                    return Some(get_node_text(&child, source).to_string());
                }
            }
        }
        None
    }

    /// Find the size expression in an array declarator
    fn find_array_size<'a>(&self, array_decl: &'a Node<'a>) -> Option<Node<'a>> {
        // Array declarator structure: declarator '[' size? ']'
        for i in 0..array_decl.child_count() {
            if let Some(child) = array_decl.child(i) {
                // Skip declarator and brackets
                if child.kind() != "[" && child.kind() != "]" {
                    // This could be the declarator (identifier) or the size
                    if child.kind() == "number_literal"
                        || child.kind() == "identifier"
                        || child.kind() == "binary_expression"
                    {
                        // If it's a number literal, this is the size
                        if child.kind() == "number_literal" {
                            return Some(child);
                        }
                    }
                }
            }
        }
        // Check for nested structure
        for i in 0..array_decl.child_count() {
            if let Some(child) = array_decl.child(i) {
                if child.kind() == "number_literal" {
                    return Some(child);
                }
            }
        }
        None
    }

    /// Get the context where a literal appears
    fn get_literal_context(&self, node: &Node) -> String {
        if let Some(parent) = node.parent() {
            match parent.kind() {
                "binary_expression" => "comparison".to_string(),
                "call_expression" => "function_argument".to_string(),
                "argument_list" => "function_argument".to_string(),
                "assignment_expression" => "assignment".to_string(),
                "init_declarator" => "initialization".to_string(),
                "array_declarator" => "array_size".to_string(),
                "for_statement" => "loop".to_string(),
                "while_statement" => "loop".to_string(),
                _ => "other".to_string(),
            }
        } else {
            "unknown".to_string()
        }
    }

    /// Check if context is suspicious for magic numbers
    fn is_suspicious_context(&self, context: &str) -> bool {
        matches!(context, "comparison" | "function_argument")
    }

    /// If `node` is a direct operand of a `binary_expression`, return the text of
    /// that expression's operator (e.g. "<<", "&", "*", "<="). Empty string otherwise.
    fn get_binary_operator(&self, node: &Node, source: &str) -> String {
        node.parent()
            .filter(|p| p.kind() == "binary_expression")
            .and_then(|p| p.child_by_field_name("operator"))
            .map(|op| get_node_text(&op, source).to_string())
            .unwrap_or_default()
    }

    /// Narrow, context-gated exemptions for well-known numeric idioms that don't
    /// obscure intent even though they're "magic numbers" in the literal sense.
    /// Each exemption is gated on BOTH the literal's normalized value AND the
    /// specific operator it's an operand of, so these values are still flagged
    /// everywhere else (e.g. `8` in an unrelated comparison is not exempted).
    fn is_well_known_idiom(&self, value: &str, operator: &str) -> bool {
        let normalized = Self::normalize_int_literal(value);

        match normalized.as_str() {
            // Byte-shift widths: standard byte-packing/unpacking idiom, e.g.
            // `(a << 24) | (b << 16) | (c << 8) | d` for IPv4 octet packing.
            "8" | "16" | "24" => operator == "<<" || operator == ">>",
            // 0xff as a byte mask: `x & 0xff`, `(x >> 8) & 0xff`, etc.
            "255" => operator == "&",
            // 1024 / KB-MB conversion factor: `size / 1024`, `n * 1024 * 1024UL`.
            "1024" => operator == "*" || operator == "/",
            // 65535: well-known max TCP port / max uint16, in a bounds check.
            "65535" => matches!(operator, "<" | "<=" | ">" | ">=" | "==" | "!="),
            _ => false,
        }
    }

    /// Structural exemption (bmdb an earlier fix, rounds 181-184): a literal whose
    /// exact hex value is echoed in the name of a SIBLING argument in the same
    /// call is a mechanical table entry pairing a value with its own already-
    /// descriptive identifier, e.g. `init_idt_entry(idt, 0x19, int_19)` --
    /// confirmed FP in 48+ instances across seL4's x86 IDT vector-index
    /// tables, always in this exact shape and with zero exceptions found.
    ///
    /// Deliberately narrow: requires the literal to be a direct, bare
    /// argument_list child (a lone call argument, not nested in a further
    /// expression) with a SIBLING argument whose identifier name ends in
    /// `_<hex>` (case-insensitive) matching this literal's own hex digits.
    /// An unrelated identifier coincidentally ending in the same hex suffix
    /// as an adjacent, unrelated literal is not a shape this codebase's
    /// audited corpora have ever produced.
    fn value_echoed_in_sibling_identifier(&self, node: &Node, source: &str) -> bool {
        let Some(parent) = node.parent() else {
            return false;
        };
        if parent.kind() != "argument_list" {
            return false;
        }
        let hex = Self::normalize_int_literal_hex(get_node_text(node, source));
        let Some(hex) = hex else {
            return false;
        };
        let suffix = format!("_{hex}");

        let mut cursor = parent.walk();
        for sibling in parent.children(&mut cursor) {
            if sibling.id() == node.id() || sibling.kind() != "identifier" {
                continue;
            }
            let name = get_node_text(&sibling, source).to_lowercase();
            if name.ends_with(&suffix) {
                return true;
            }
        }
        false
    }

    /// Lowercase hex digits of an integer literal (no `0x`/sign/suffix), or
    /// `None` if it isn't an integer literal at all (floats, strings).
    fn normalize_int_literal_hex(value: &str) -> Option<String> {
        let trimmed = value.trim().trim_start_matches('-');
        let stripped = trimmed.trim_end_matches(['u', 'U', 'l', 'L']);
        if stripped.is_empty() || stripped.contains('.') {
            return None;
        }
        if let Some(hex) = stripped
            .strip_prefix("0x")
            .or_else(|| stripped.strip_prefix("0X"))
        {
            return Some(hex.to_lowercase());
        }
        let n: u64 = stripped.parse().ok()?;
        Some(format!("{n:x}"))
    }

    /// Structural exemption (bmdb an earlier fix, rounds 181-184): a literal
    /// compared directly against an identifier whose name is a well-known
    /// library/platform version macro is a version-check idiom, not hidden
    /// program logic -- confirmed FP in 19 instances spanning ARES_VERSION,
    /// NGHTTP2_VERSION_NUM, LIBWOLFSSL_VERSION_HEX, GNUTLS_VERSION_NUMBER,
    /// MBEDTLS_VERSION_NUMBER, OPENSSL_VERSION_NUMBER, OPENSSL_API_LEVEL,
    /// LWS_LIBRARY_VERSION_NUMBER, CJSON_VERSION_FULL,
    /// __IPHONE_OS_VERSION_MAX_ALLOWED, __MAC_OS_X_VERSION_MAX_ALLOWED and
    /// _MSC_VER, across curl/hostap/mosquitto/raylib. Zero exceptions found.
    ///
    /// The same idiom spelled as a version ACCESSOR CALL rather than a macro
    /// -- `sqlite3_libversion_number() >= 3008002`, curl's
    /// `Curl_conn_http_version(data, conn) != 20` -- is the same check
    /// against a runtime library version, and is recognized by the same
    /// name predicate applied to the callee (mechanism 4).
    fn is_version_macro_comparison(&self, node: &Node, source: &str) -> bool {
        let Some(parent) = node.parent() else {
            return false;
        };
        if parent.kind() != "binary_expression" {
            return false;
        }
        let other = match (
            parent.child_by_field_name("left"),
            parent.child_by_field_name("right"),
        ) {
            (Some(left), Some(right)) if left.id() == node.id() => right,
            (Some(left), Some(right)) if right.id() == node.id() => left,
            _ => return false,
        };
        let named = match other.kind() {
            "identifier" => other,
            "call_expression" => match other.child_by_field_name("function") {
                Some(f) if f.kind() == "identifier" => f,
                _ => return false,
            },
            _ => return false,
        };
        Self::is_version_macro_identifier(&get_node_text(&named, source).to_lowercase())
    }

    /// Structural exemption (mechanism 3): a literal that an
    /// assertion pins a NAMED quantity to. `assert( sizeof(aSpecial)==32 )`,
    /// `assert( PAGER_JOURNALMODE_WAL==5 )`, `assert( 200==sqlite3LogEst(
    /// 1048576) )`: the literal is not program logic, it is the checked
    /// statement about the program's constants, and the "compliant" rewrite
    /// -- replace it with the constant -- makes the assertion `X == X`. The
    /// version-macro exemption above is the special case of this for one
    /// family of names; this is the general shape, kept narrow:
    ///
    /// - the literal is a DIRECT operand of `==` or `!=` (a literal folded
    ///   into arithmetic or a mask on one side is still a magic number);
    /// - the other operand is a named quantity (`is_named_quantity`): an
    ///   ALL_CAPS identifier, a `sizeof`, a call, or an arithmetic
    ///   combination of those;
    /// - the comparison reaches an assert-family callee (`assert`,
    ///   `static_assert`, `DEBUGASSERT`, ...: any name containing "assert",
    ///   case-insensitive) through parentheses only.
    ///
    /// The literal's OTHER occurrences are unaffected; only the operand of
    /// the assertion itself is exempt, so `assert(200==f(1048576))` still
    /// reports the 1048576 argument.
    fn is_consistency_assert_operand(&self, node: &Node, source: &str) -> bool {
        let Some(parent) = node.parent() else {
            return false;
        };
        if parent.kind() != "binary_expression" {
            return false;
        }
        let op = parent
            .child_by_field_name("operator")
            .map(|o| get_node_text(&o, source))
            .unwrap_or_default();
        if op != "==" && op != "!=" {
            return false;
        }
        let other = match (
            parent.child_by_field_name("left"),
            parent.child_by_field_name("right"),
        ) {
            (Some(left), Some(right)) if left.id() == node.id() => right,
            (Some(left), Some(right)) if right.id() == node.id() => left,
            _ => return false,
        };
        if !Self::is_named_quantity(&other, source) {
            return false;
        }
        // Walk up through parentheses to the argument list of the assert.
        let mut cur = parent;
        loop {
            let Some(up) = cur.parent() else {
                return false;
            };
            match up.kind() {
                "parenthesized_expression" => cur = up,
                "argument_list" => {
                    return up
                        .parent()
                        .filter(|call| call.kind() == "call_expression")
                        .and_then(|call| call.child_by_field_name("function"))
                        .is_some_and(|f| {
                            get_node_text(&f, source).to_lowercase().contains("assert")
                        });
                }
                _ => return false,
            }
        }
    }

    /// Is this operand a quantity the program already names, rather than a
    /// value spelled out on the spot? An ALL_CAPS identifier (a macro or
    /// enumerator by convention), a `sizeof`, or a call -- and, since the
    /// assert's other side is just as self-documenting when it is those
    /// combined, an arithmetic expression EVERY leaf of which is one of
    /// them: sqlite's `assert( 121 == WALINDEX_LOCK_OFFSET + WAL_CKPT_LOCK )`
    /// and the `WALINDEX_LOCK_OFFSET + WAL_READ_LOCK(n)` rows beside it
    /// (the bare-identifier block above them was already exempt).
    ///
    /// The guarantee stays mechanical rather than inferred: a single bare
    /// literal leaf (`WALINDEX_LOCK_OFFSET + 3`) makes the whole operand not
    /// a named quantity, and only `+ - * / %` compose -- a mask or shift
    /// assembles a value rather than naming one.
    fn is_named_quantity(node: &Node, source: &str) -> bool {
        match node.kind() {
            "sizeof_expression" | "call_expression" => true,
            "identifier" => {
                let name = get_node_text(node, source);
                name.chars().any(|c| c.is_ascii_alphabetic())
                    && !name.chars().any(|c| c.is_ascii_lowercase())
            }
            "parenthesized_expression" => node
                .named_child(0)
                .is_some_and(|inner| Self::is_named_quantity(&inner, source)),
            "binary_expression" => {
                let arithmetic = node
                    .child_by_field_name("operator")
                    .map(|op| get_node_text(&op, source))
                    .is_some_and(|op| matches!(op, "+" | "-" | "*" | "/" | "%"));
                arithmetic
                    && node
                        .child_by_field_name("left")
                        .zip(node.child_by_field_name("right"))
                        .is_some_and(|(l, r)| {
                            Self::is_named_quantity(&l, source)
                                && Self::is_named_quantity(&r, source)
                        })
            }
            _ => false,
        }
    }

    /// A handful of macros (OPENSSL_API_LEVEL) don't contain "version" or
    /// end in "_ver" but are just as well-known a version-check idiom as
    /// the ones that do -- named explicitly rather than pattern-matched, so
    /// this exemption stays evidence-based rather than a guess at more
    /// macros that might exist.
    const NAMED_VERSION_MACROS: &'static [&'static str] = &["openssl_api_level"];

    fn is_version_macro_identifier(name_lower: &str) -> bool {
        name_lower.contains("version")
            || name_lower.ends_with("_ver")
            || Self::NAMED_VERSION_MACROS.contains(&name_lower)
    }

    /// Normalize an integer literal's text to its decimal value for comparison
    /// against well-known idiom constants, stripping unsigned/long suffixes and
    /// resolving hex or octal form (e.g. "0xff", "0XFF", "255UL", and the C
    /// octal literal "0377", all normalize to "255").
    fn normalize_int_literal(value: &str) -> String {
        let trimmed = value.trim();
        let stripped = trimmed.trim_end_matches(['u', 'U', 'l', 'L']);

        if let Some(hex) = stripped
            .strip_prefix("0x")
            .or_else(|| stripped.strip_prefix("0X"))
        {
            if let Ok(n) = u64::from_str_radix(hex, 16) {
                return n.to_string();
            }
        }

        // C octal literal: a leading '0' followed by one or more further
        // octal digits (0-7) and nothing else, e.g. "0007", "0777", "0600".
        // A bare "0" is left alone -- its decimal and octal values are the
        // same digit anyway, and it isn't "0" followed by more digits.
        if stripped.len() > 1
            && stripped.starts_with('0')
            && stripped.as_bytes()[1..]
                .iter()
                .all(|b| b.is_ascii_digit() && *b < b'8')
        {
            if let Ok(n) = u64::from_str_radix(&stripped[1..], 8) {
                return n.to_string();
            }
        }

        stripped.to_string()
    }

    /// Check if a literal value is acceptable (common non-magic values)
    fn is_acceptable_literal(&self, value: &str) -> bool {
        let trimmed = value.trim();

        // Handle negative numbers
        if let Some(positive) = trimmed.strip_prefix('-') {
            return self.is_acceptable_literal(positive);
        }

        // Strip float/unsigned suffixes: 0.0f, 1.0F, 0u, 0U, 0L, 0UL, etc.
        let stripped = trimmed.trim_end_matches(['f', 'F', 'u', 'U', 'l', 'L']);

        // Accept zero in any float form: 0.0, 0.0f, 0.0F
        if stripped == "0.0" || stripped == "0." || stripped == ".0" {
            return true;
        }

        // Accept small float literals: 1.0f, 2.0f, etc.
        if let Some(int_part) = stripped.strip_suffix(".0") {
            if self.is_acceptable_integer(int_part) {
                return true;
            }
        }

        self.is_acceptable_integer(stripped)
    }

    fn is_acceptable_integer(&self, value: &str) -> bool {
        // Common acceptable values: 0-10, spelled in any base. Compares the
        // normalized decimal value rather than a fixed set of spellings, so
        // "0x8", "0x06", "0007" (decimal 8, 6, 7) are recognized the same as
        // "8", "6", "7" -- previously only "0x0"/"0x1"/"0x2" were accepted in
        // hex form at all, and octal spellings were never normalized, so a
        // small in-range value written in an unlisted base was flagged as a
        // magic number purely because of how it was spelled, not its value.
        matches!(Self::normalize_int_literal(value).parse::<i64>(), Ok(n) if (0..=10).contains(&n))
    }

    /// The names `sizeof` is applied to in this file, used to exempt an
    /// array whose declared size is a literal but whose extent the code
    /// takes with `sizeof` rather than repeating the number (the CERT wiki's
    /// own compliant `sizeof` example).
    ///
    /// Read from the tree, not from the text between the parentheses: the
    /// text scan required a `(` and a space-free operand, so `sizeof buf`
    /// (the K&R spelling, valid C) yielded nothing at all, and `sizeof(x.a)`
    /// yielded "x.a", which never matches the declarator name `a` -- both
    /// left an array that IS measured with `sizeof` reported as if it were
    /// not (mechanisms 7 and 8). The operand is unwrapped through
    /// any parentheses; a plain identifier names itself, and a field access
    /// (`x.a`, `p->a`) names the field, which is what the array declarator
    /// inside the struct is spelled as. A subscript or deref (`sizeof
    /// buf[0]`, `sizeof *p`) measures an element, not the array, and is
    /// deliberately not credited.
    fn find_sizeof_usages(&self, node: &Node, source: &str) -> HashSet<String> {
        query::find_descendants_of_kind(*node, "sizeof_expression")
            .into_iter()
            .filter_map(|n| {
                let mut operand = n.child_by_field_name("value")?;
                while operand.kind() == "parenthesized_expression" {
                    operand = operand.named_child(0)?;
                }
                match operand.kind() {
                    "identifier" => Some(get_node_text(&operand, source).to_string()),
                    "field_expression" => operand
                        .child_by_field_name("field")
                        .map(|f| get_node_text(&f, source).to_string()),
                    _ => None,
                }
            })
            .collect()
    }
}
