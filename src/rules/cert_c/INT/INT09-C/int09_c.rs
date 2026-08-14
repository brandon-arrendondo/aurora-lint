//! INT09-C: Ensure enumeration constants map to unique values
//!
//! When enumeration constants are assigned explicit values, mixing explicit and
//! implicit assignments can lead to unintentional duplicate values. This can cause
//! problems in switch statements where multiple case labels may have the same value.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! enum Color { red=4, orange, yellow, green, blue, indigo=6, violet };
//! // yellow=6 (implicit), indigo=6 (explicit) - DUPLICATE!
//! // green=7 (implicit), violet=7 (implicit) - DUPLICATE!
//! ```
//!
//! **Compliant:**
//! ```c
//! enum Color { red, orange, yellow, green, blue, indigo, violet };
//! // All implicit - sequential 0-6, no duplicates
//!
//! enum Color { red=4, orange, yellow, green, blue, indigo, violet };
//! // Only first explicit, rest sequential - no duplicates
//!
//! enum Color { red=4, orange=5, yellow=6, green=7, blue=8, indigo=6, violet=7 };
//! // All explicit - duplicates are INTENTIONAL (allowed)
//! ```

use super::super::{CertRule, RuleViolation};
use crate::analyze::const_eval::{
    collect_macro_constants, try_evaluate_text_public, MacroConstantMap,
};
use crate::manifest::{RuleCategory, Severity};
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

// Track enumerator values and whether they're explicit.
#[derive(Debug)]
struct EnumValue {
    name: String,
    value: i64,
    is_explicit: bool,
    // True when the explicit value is derived from a prior enumerator's
    // NAME, either directly (`violet = indigo`) or through arithmetic on it
    // (`FOO_MAX = __FOO_AFTER_LAST - 1`, the standard MAX-sentinel idiom,
    // which by construction duplicates the last real member's value on
    // purpose). Referencing a named enumerator can't collide by accident
    // the way a numeric-literal collision can, so it's unambiguous
    // intentional duplication (CERT INT09-C's own exception).
    is_name_alias: bool,
    line: usize,
    column: usize,
}

pub struct Int09C;

impl CertRule for Int09C {
    fn rule_id(&self) -> &'static str {
        "INT09-C"
    }

    fn description(&self) -> &'static str {
        "Ensure enumeration constants map to unique values"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "INT09-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_enum_duplicates(node, source, violations);
    }
}

impl Int09C {
    fn check_enum_duplicates(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let macros = collect_macro_constants(node, source);
        let line_starts = Self::build_line_starts(source);
        // Names of every enumerator in the whole file, not just the current
        // enum -- some codebases (e.g. hostap/QCA's netlink-attribute
        // headers) bound one enum's MAX sentinel against a *different*
        // enum's member (`_MAX = OUTER_ENUM_ATTR - 1`, a deliberate
        // "this attribute's own container slot" convention), which is just
        // as unambiguously intentional as the same-enum `violet = indigo`
        // case CERT's exception already covers.
        let all_enum_names: HashSet<String> = query::find_descendants_of_kind(*node, "enumerator")
            .into_iter()
            .filter_map(|e| {
                e.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                    .map(|s| s.to_string())
            })
            .collect();
        for n in query::find_descendants_of_kind(*node, "enum_specifier") {
            self.analyze_enum(
                &n,
                source,
                &macros,
                &all_enum_names,
                &line_starts,
                violations,
            );
        }
    }

    fn analyze_enum(
        &self,
        enum_node: &Node,
        source: &str,
        macros: &MacroConstantMap,
        all_enum_names: &HashSet<String>,
        line_starts: &[usize],
        violations: &mut Vec<RuleViolation>,
    ) {
        // Find the enumerator_list
        let enumerator_list = match Self::find_enumerator_list(enum_node) {
            Some(list) => list,
            None => return,
        };

        // Re-derive each enumerator from the raw source text between the
        // list's braces, splitting on top-level commas, rather than relying
        // on tree-sitter's `enumerator`/`value` node fields directly. A
        // trailing attribute-position macro with call syntax between an
        // enumerator's name and its `=` initializer (e.g. curl's
        // `NAME CURL_DEPRECATED(ver, "msg") = EXPR`) produces ERROR nodes
        // that fragment the AST into extra phantom `enumerator` siblings
        // with no `value` field (task 453) -- operating on raw text instead
        // sidesteps that corrupted structure entirely.
        let list_start = enumerator_list.start_byte();
        let list_end = enumerator_list.end_byte();
        let inner_start = list_start + 1; // skip '{'
        let inner_end = list_end.saturating_sub(1); // skip '}'
        if inner_end <= inner_start || inner_end > source.len() {
            return;
        }
        let list_text = &source[inner_start..inner_end];

        let mut enumerators: Vec<EnumValue> = Vec::new();
        let mut current_value: i64 = 0;

        for (rel_start, rel_end) in Self::split_top_level_commas(list_text) {
            let raw_entry = &list_text[rel_start..rel_end];
            let stripped = Self::strip_comments(raw_entry);
            let Some(name) = Self::extract_name(&stripped) else {
                continue;
            };
            let name = name.to_string();

            let (value, is_explicit, is_name_alias) = match Self::find_top_level_value(&stripped) {
                Some(value_text) => {
                    let trimmed = value_text.trim();
                    // An explicit value may reference a prior
                    // enumerator by name (e.g. `violet = indigo`)
                    // rather than a numeric literal; resolve it
                    // against what's been parsed so far before
                    // falling back to numeric parsing.
                    if let Some(aliased) = enumerators.iter().find(|e| e.name == trimmed) {
                        (aliased.value, true, true)
                    } else if let Some((v, used_enum_ref)) =
                        self.try_eval_enum_arith(trimmed, &enumerators)
                    {
                        (v, true, used_enum_ref)
                    } else if let Some(v) = try_evaluate_text_public(trimmed, macros) {
                        // Handles arithmetic on plain `#define` macros
                        // (e.g. curl's `CURLINFO_STRING + 1` idiom), which
                        // aren't prior enumerators so try_eval_enum_arith
                        // can't resolve them. If the expression also
                        // references another enumerator's name -- from this
                        // enum or (unlike try_eval_enum_arith) any other
                        // enum in the file -- treat it as an intentional
                        // name-derived duplicate, same as the same-enum case
                        // above.
                        let is_name_ref =
                            Self::text_references_known_enum_name(trimmed, all_enum_names);
                        (v, true, is_name_ref)
                    } else {
                        (self.parse_constant_value(trimmed), true, false)
                    }
                }
                None => (current_value, false, false),
            };

            let name_offset_in_entry = raw_entry.find(name.as_str()).unwrap_or(0);
            let abs_offset = inner_start + rel_start + name_offset_in_entry;
            let (line, column) = Self::line_col_from_starts(line_starts, abs_offset);

            enumerators.push(EnumValue {
                name,
                value,
                is_explicit,
                is_name_alias,
                line,
                column,
            });

            current_value = value + 1;
        }

        // Check for duplicates where at least one is implicit (unintentional)
        let mut value_map: HashMap<i64, Vec<&EnumValue>> = HashMap::new();
        for enumerator in &enumerators {
            value_map
                .entry(enumerator.value)
                .or_default()
                .push(enumerator);
        }

        for (value, enum_list) in value_map {
            if enum_list.len() > 1 {
                // Check if at least one is implicit (unintentional duplicate)
                let has_implicit = enum_list.iter().any(|e| !e.is_explicit);
                // A direct by-name alias (e.g. `violet = indigo`) can't be
                // an accidental collision -- it's unambiguous intentional
                // duplication, regardless of whether the aliased value
                // happened to be implicit.
                let has_name_alias = enum_list.iter().any(|e| e.is_name_alias);

                if has_implicit && !has_name_alias {
                    // Report violation for all duplicates
                    for enumerator in enum_list {
                        let explicit_status = if enumerator.is_explicit {
                            "explicitly"
                        } else {
                            "implicitly"
                        };

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            message: format!(
                                "Enumeration constant '{}' has duplicate value {} ({}). \
                                 Mixing explicit and implicit enum value assignments can \
                                 cause unintentional duplicates.",
                                enumerator.name, value, explicit_status
                            ),
                            severity: self.severity(),
                            line: enumerator.line,
                            column: enumerator.column,
                            file_path: String::new(),
                            suggestion: Some(
                                "Either use all implicit values, or make all assignments explicit"
                                    .to_string(),
                            ),
                            requires_manual_review: Some(false),
                        });
                    }
                }
            }
        }
    }

    fn find_enumerator_list<'a>(enum_node: &'a Node<'a>) -> Option<Node<'a>> {
        for i in 0..enum_node.child_count() {
            if let Some(child) = enum_node.child(i) {
                if child.kind() == "enumerator_list" {
                    return Some(child);
                }
            }
        }
        None
    }

    /// Split `text` into byte ranges delimited by top-level commas --
    /// commas inside `()`/`[]`/`{}` nesting, string/char literals, or
    /// `/* */`/`//` comments don't count as separators. This is what lets a
    /// malformed attribute-macro call (e.g. `CURL_DEPRECATED(7.55, "a, b")`)
    /// stay part of the same enumerator entry instead of splitting on its
    /// internal comma.
    fn split_top_level_commas(text: &str) -> Vec<(usize, usize)> {
        let mut entries = Vec::new();
        let mut depth = 0i32;
        let mut in_str: Option<u8> = None;
        let mut start = 0usize;
        let bytes = text.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            let c = bytes[i];
            if let Some(q) = in_str {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    in_str = None;
                }
                i += 1;
                continue;
            }
            if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
                continue;
            }
            if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            match c {
                b'"' | b'\'' => {
                    in_str = Some(c);
                    i += 1;
                }
                b'(' | b'[' | b'{' => {
                    depth += 1;
                    i += 1;
                }
                b')' | b']' | b'}' => {
                    depth -= 1;
                    i += 1;
                }
                b',' if depth == 0 => {
                    entries.push((start, i));
                    start = i + 1;
                    i += 1;
                }
                _ => {
                    i += 1;
                }
            }
        }
        entries.push((start, bytes.len()));
        entries
    }

    /// Remove `/* */` and `//` comments from `text`, preserving everything
    /// else verbatim (including string/char literal contents).
    fn strip_comments(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '/' && chars.peek() == Some(&'*') {
                chars.next();
                let mut prev = '\0';
                for c2 in chars.by_ref() {
                    if prev == '*' && c2 == '/' {
                        break;
                    }
                    prev = c2;
                }
            } else if c == '/' && chars.peek() == Some(&'/') {
                for c2 in chars.by_ref() {
                    if c2 == '\n' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    /// Extract the leading C identifier from `text` (after trimming leading
    /// whitespace) -- an enumerator entry's name always comes first.
    fn extract_name(text: &str) -> Option<&str> {
        let trimmed = text.trim_start();
        let mut end = 0usize;
        for (i, c) in trimmed.char_indices() {
            if i == 0 {
                if !(c.is_ascii_alphabetic() || c == '_') {
                    return None;
                }
            } else if !(c.is_ascii_alphanumeric() || c == '_') {
                break;
            }
            end = i + c.len_utf8();
        }
        if end == 0 {
            None
        } else {
            Some(&trimmed[..end])
        }
    }

    /// True if any identifier token in `text` matches a known enumerator
    /// name (from anywhere in the file). Used to recognize a cross-enum
    /// name reference as intentional, not just cross-enum arithmetic that
    /// happens to numerically collide.
    fn text_references_known_enum_name(text: &str, known_names: &HashSet<String>) -> bool {
        let bytes = text.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                if known_names.contains(&text[start..i]) {
                    return true;
                }
            } else {
                i += 1;
            }
        }
        false
    }

    /// Find the value-initializer text after the last top-level `=` in
    /// `text` (depth-0, outside string/char literals, and not part of a
    /// `==`/`!=`/`<=`/`>=` comparison operator). Returns `None` when there's
    /// no explicit initializer -- including when the only `=` found is
    /// buried inside a malformed attribute-macro call's parens, which this
    /// depth tracking correctly ignores.
    fn find_top_level_value(text: &str) -> Option<&str> {
        let bytes = text.as_bytes();
        let mut depth = 0i32;
        let mut in_str: Option<u8> = None;
        let mut last_eq: Option<usize> = None;
        let mut i = 0usize;
        while i < bytes.len() {
            let c = bytes[i];
            if let Some(q) = in_str {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    in_str = None;
                }
                i += 1;
                continue;
            }
            match c {
                b'"' | b'\'' => in_str = Some(c),
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth -= 1,
                b'=' if depth == 0 => {
                    let prev = if i > 0 { bytes[i - 1] } else { 0 };
                    let next = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
                    if next != b'=' && prev != b'=' && prev != b'!' && prev != b'<' && prev != b'>'
                    {
                        last_eq = Some(i);
                    }
                }
                _ => {}
            }
            i += 1;
        }
        last_eq.map(|pos| text[pos + 1..].trim())
    }

    /// Byte offsets of the start of each line in `source` (index 0 is
    /// always line 1's start at offset 0).
    fn build_line_starts(source: &str) -> Vec<usize> {
        let mut starts = vec![0usize];
        for (i, b) in source.bytes().enumerate() {
            if b == b'\n' {
                starts.push(i + 1);
            }
        }
        starts
    }

    /// Convert a byte offset into 1-based (line, column), using the
    /// precomputed `line_starts` table.
    fn line_col_from_starts(line_starts: &[usize], offset: usize) -> (usize, usize) {
        let idx = match line_starts.binary_search(&offset) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        let line_start = line_starts.get(idx).copied().unwrap_or(0);
        (idx + 1, offset.saturating_sub(line_start) + 1)
    }

    /// Try to evaluate a simple `LHS (+|-) RHS` expression where either side
    /// may be a numeric literal or the name of a prior enumerator in the
    /// same enum (e.g. `NUM_FOO - 1`, `__FOO_AFTER_LAST - 1`). Returns the
    /// computed value plus whether either operand was a named-enumerator
    /// reference (as opposed to two plain numeric literals).
    ///
    /// Scans for the operator right-to-left so the split lands on the
    /// top-level `+`/`-` for the single-operator idiom this rule cares
    /// about; it does not attempt general expression parsing (precedence,
    /// parens, multiple operators).
    fn try_eval_enum_arith(&self, text: &str, enumerators: &[EnumValue]) -> Option<(i64, bool)> {
        for (idx, ch) in text.char_indices().rev() {
            if (ch == '+' || ch == '-') && idx != 0 {
                let left = text[..idx].trim();
                let right = text[idx + ch.len_utf8()..].trim();
                if left.is_empty() || right.is_empty() {
                    continue;
                }
                if let (Some((lval, lref)), Some((rval, rref))) = (
                    self.resolve_enum_operand(left, enumerators),
                    self.resolve_enum_operand(right, enumerators),
                ) {
                    let result = if ch == '+' { lval + rval } else { lval - rval };
                    return Some((result, lref || rref));
                }
            }
        }
        None
    }

    /// Resolve one operand of an enum-initializer arithmetic expression:
    /// either a prior enumerator's name (returns its value, `true`) or a
    /// numeric literal (returns its value, `false`).
    fn resolve_enum_operand(&self, text: &str, enumerators: &[EnumValue]) -> Option<(i64, bool)> {
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        if let Some(e) = enumerators.iter().find(|e| e.name == text) {
            return Some((e.value, true));
        }
        if text.starts_with("0x") || text.starts_with("0X") {
            return i64::from_str_radix(&text[2..], 16).ok().map(|v| (v, false));
        }
        if text.chars().all(|c| c.is_ascii_digit()) {
            return text.parse::<i64>().ok().map(|v| (v, false));
        }
        None
    }

    fn parse_constant_value(&self, text: &str) -> i64 {
        let text = text.trim();

        // Handle hex
        if text.starts_with("0x") || text.starts_with("0X") {
            return i64::from_str_radix(&text[2..], 16).unwrap_or(0);
        }

        // Handle octal
        if text.starts_with('0') && text.len() > 1 {
            return i64::from_str_radix(text, 8).unwrap_or(0);
        }

        // Handle decimal
        text.parse::<i64>().unwrap_or(0)
    }
}
