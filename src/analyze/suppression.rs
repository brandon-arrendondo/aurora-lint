use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

/// Maximum number of lines a suppress comment can appear before the violation it covers.
const MAX_PROXIMITY: usize = 5;

/// An inline `SQC-SUPPRESS` comment, parsed from a source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suppression {
    /// The rule ID being suppressed.
    pub rule_id: String,
    /// Hash of the suppressed line's code, for tamper detection.
    pub hash: String,
    /// Justification text from the comment.
    pub justification: String,
    /// 1-based line number of the suppress comment in the source file.
    /// 0 means this came from a TOML file (no proximity check).
    pub comment_line: usize,
}

/// A single `[[suppress]]` entry in the shared `suppress.toml` (see
/// `lang_parsing_substrate/docs/unified-config-spec.md`). One file, all
/// tools — `tool` scopes each entry to `"sqc"` or the wildcard `"*"`;
/// entries for other tools (e.g. `"knots"`) are loaded and ignored.
///
/// `rule_glob` and `function_prefix` are sqc-specific extensions beyond the
/// base spec, preserving CERT-C rule-family and identifier-prefix
/// suppression that predates this migration.
///
/// An entry is either hash-matched (`hash` + `file` + `rule` all present —
/// exact code match, tamper-detected) or a wildcard suppression (no `hash`;
/// at least one of `file_glob`, `rule`, `rule_glob`, `function_prefix`).
#[derive(Debug, Clone, Deserialize)]
pub struct SuppressEntry {
    /// Human-readable label, unique within the file.
    pub name: String,
    /// `"sqc"`, or `"*"` to apply across every tool.
    pub tool: String,
    /// Exact rule ID this entry applies to.
    #[serde(default)]
    pub rule: Option<String>,
    /// Exact file path this entry applies to.
    #[serde(default)]
    pub file: Option<String>,
    /// Glob pattern for file paths (e.g., `"src/vendor/**"`, `"**/*.generated.c"`).
    #[serde(default)]
    pub file_glob: Option<String>,
    /// Required for hash-matched entries; omit for wildcard entries.
    #[serde(default)]
    pub hash: Option<String>,
    /// Glob pattern for rule IDs (e.g., `"DCL*"`, `"INT3*-C"`) — sqc extension.
    #[serde(default)]
    pub rule_glob: Option<String>,
    /// Prefix to match in violation messages (e.g., `"wolfSSL_"`) — sqc extension.
    /// Matches if the message contains an identifier starting with this prefix.
    #[serde(default)]
    pub function_prefix: Option<String>,
    /// Justification text shown alongside the suppression.
    #[serde(default)]
    pub justification: String,
}

/// A wildcard entry, compiled from a [`SuppressEntry`] that has no `hash`.
///
/// All specified fields are ANDed: a violation must match every field present.
/// At least one matching field (file_glob, rule, rule_glob, function_prefix) must be set.
#[derive(Debug, Clone)]
struct WildcardSpec {
    file_glob: Option<String>,
    rule: Option<String>,
    rule_glob: Option<String>,
    function_prefix: Option<String>,
    justification: String,
}

/// Compiled wildcard suppression, ready for matching.
#[derive(Clone)]
struct CompiledWildcard {
    file_glob: Option<regex::Regex>,
    rule: Option<String>,
    rule_glob: Option<regex::Regex>,
    function_prefix: Option<String>,
    justification: String,
}

/// Top-level structure of `suppress.toml`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SuppressFile {
    /// Every `[[suppress]]` entry in the file.
    #[serde(default)]
    pub suppress: Vec<SuppressEntry>,
}

impl Suppression {
    /// Parse a SQC-SUPPRESS directive from a comment.
    ///
    /// `line_number` is 0-based (from enumerate). The comment may be a standalone
    /// line (`// SQC-SUPPRESS: ...`) or an inline suffix on a code line.
    pub fn parse(comment: &str, line_number: usize) -> Option<Self> {
        if !comment.contains("SQC-SUPPRESS") {
            return None;
        }

        let rule_id = Self::extract_rule_id(comment)?;
        let hash = Self::extract_hash(comment)?;
        let justification = Self::extract_justification(comment).unwrap_or_default();

        Some(Suppression {
            rule_id,
            hash,
            justification,
            comment_line: line_number + 1, // convert to 1-based
        })
    }

    /// Check whether this suppression matches a violation on `violation_line` (1-based).
    ///
    /// Two checks:
    /// 1. Proximity — comment is on the same line or up to MAX_PROXIMITY lines before
    ///    (skipped for TOML entries where comment_line == 0)
    /// 2. Hash — SHA-256 of (rule_id + normalized violation line) matches stored hash
    pub fn matches(&self, source: &str, violation_line: usize) -> bool {
        // Skip proximity check for TOML-sourced suppressions (comment_line == 0)
        if self.comment_line > 0 {
            if self.comment_line > violation_line
                || violation_line - self.comment_line > MAX_PROXIMITY
            {
                return false;
            }
        }

        // Hash the violation line (stripping any inline SQC-SUPPRESS comment)
        let code = Self::get_line(source, violation_line);
        let code = Self::strip_suppress_comment(&code);
        let current_hash = SuppressionManager::calculate_suppression_hash(&self.rule_id, &code);
        current_hash == self.hash
    }

    /// Get a single 1-based line from source.
    fn get_line(source: &str, line: usize) -> String {
        source
            .lines()
            .nth(line.saturating_sub(1))
            .unwrap_or("")
            .to_string()
    }

    /// Strip an inline `// SQC-SUPPRESS...` suffix from a code line so the hash
    /// covers only the code portion.
    fn strip_suppress_comment(line: &str) -> String {
        if let Some(pos) = line.find("// SQC-SUPPRESS") {
            line[..pos].to_string()
        } else if let Some(pos) = line.find("/* SQC-SUPPRESS") {
            line[..pos].to_string()
        } else {
            line.to_string()
        }
    }

    fn extract_rule_id(comment: &str) -> Option<String> {
        let re = regex::Regex::new(r"SQC-SUPPRESS:\s*([A-Z0-9]+-[A-Z0-9]+)").ok()?;
        re.captures(comment)?.get(1).map(|m| m.as_str().to_string())
    }

    fn extract_hash(comment: &str) -> Option<String> {
        let re = regex::Regex::new(r"HASH:([a-f0-9]+)").ok()?;
        re.captures(comment)?.get(1).map(|m| m.as_str().to_string())
    }

    fn extract_justification(comment: &str) -> Option<String> {
        let re = regex::Regex::new(
            r#"JUSTIFICATION:\s*"([^"]+)"|JUSTIFICATION:\s*(.+?)(?:\s+[A-Z]+:|$)"#,
        )
        .ok()?;
        re.captures(comment).and_then(|cap| {
            cap.get(1)
                .or(cap.get(2))
                .map(|m| m.as_str().trim().to_string())
        })
    }
}

/// Loaded suppressions (inline comments, `suppress.toml` entries, and
/// never-compiled dead-code ranges) and the matching logic for whether a
/// given violation is covered by any of them.
#[derive(Default, Clone)]
pub struct SuppressionManager {
    /// Inline comment suppressions, keyed by full file path.
    suppressions: HashMap<String, Vec<Suppression>>,
    /// Hash-matched suppressions loaded from `suppress.toml`'s `[[suppress]]`
    /// entries, keyed by the `file` field.
    toml_suppressions: Vec<(String, Suppression)>,
    /// Wildcard suppressions loaded from `suppress.toml`'s `[[suppress]]`
    /// entries that have no `hash`.
    wildcard_suppressions: Vec<CompiledWildcard>,
    /// 1-based inclusive line ranges never compiled when the file is built as C
    /// (`#if 0` and `__cplusplus`-gated C++-only branches), keyed by full file
    /// path. Violations landing in these ranges are suppressed because the
    /// enclosing code is never compiled in a C translation unit.
    dead_code_ranges: HashMap<String, Vec<(usize, usize)>>,
}

impl SuppressionManager {
    /// An empty manager with no suppressions loaded.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load suppressions from a `suppress.toml` (or legacy `.sqc-suppress.toml`) file.
    pub fn load_from_toml(&mut self, toml_path: &str) -> Result<usize, String> {
        let content = std::fs::read_to_string(toml_path)
            .map_err(|e| format!("Cannot read {}: {}", toml_path, e))?;
        let parsed: SuppressFile = toml::from_str(&content)
            .map_err(|e| format!("Invalid TOML in {}: {}", toml_path, e))?;

        let mut count = 0;
        for entry in parsed.suppress {
            if !(entry.tool == "sqc" || entry.tool == "*") {
                continue;
            }
            match entry.hash.clone() {
                Some(hash) => {
                    let (Some(file), Some(rule)) = (entry.file.clone(), entry.rule.clone()) else {
                        eprintln!(
                            "Warning: suppress entry '{}' has a hash but is missing file/rule; skipping",
                            entry.name
                        );
                        continue;
                    };
                    let suppression = Suppression {
                        rule_id: rule,
                        hash,
                        justification: entry.justification.clone(),
                        comment_line: 0, // sentinel: skip proximity check
                    };
                    self.toml_suppressions.push((file, suppression));
                }
                None => {
                    let spec = WildcardSpec {
                        file_glob: entry.file_glob.clone().or_else(|| entry.file.clone()),
                        rule: entry.rule.clone(),
                        rule_glob: entry.rule_glob.clone(),
                        function_prefix: entry.function_prefix.clone(),
                        justification: entry.justification.clone(),
                    };
                    let compiled = CompiledWildcard::try_from_spec(spec)
                        .map_err(|e| format!("suppress entry '{}': {}", entry.name, e))?;
                    self.wildcard_suppressions.push(compiled);
                }
            }
            count += 1;
        }

        Ok(count)
    }

    /// Extract all suppressions from source code.
    ///
    /// Scans every line for both the legacy `SQC-SUPPRESS` directive
    /// (standalone or inline on a code line — kept during the deprecation
    /// window described in `lang_parsing_substrate/docs/unified-config-spec.md`)
    /// and the shared unified `tools:suppress sqc:RULE` comment (standalone
    /// line only, matching the spec's own examples), via
    /// `lang_parsing_substrate::suppressions`.
    pub fn extract_from_source(&mut self, file_path: &str, source: &str) {
        let mut file_suppressions = Vec::new();

        for (line_num, line) in source.lines().enumerate() {
            if line.contains("SQC-SUPPRESS") {
                if let Some(suppression) = Suppression::parse(line, line_num) {
                    file_suppressions.push(suppression);
                }
            }
        }

        for s in
            lang_parsing_substrate::suppressions(source, lang_parsing_substrate::SlocMode::Default)
        {
            if !s.tool.eq_ignore_ascii_case("sqc") {
                continue;
            }
            let Some(hash) = s.hash else {
                // sqc suppressions require a HASH for tamper detection —
                // matches the legacy parser's `extract_hash` requirement.
                continue;
            };
            file_suppressions.push(Suppression {
                rule_id: s.rule,
                hash,
                justification: s.justification.unwrap_or_default(),
                comment_line: s.comment_line,
            });
        }

        if !file_suppressions.is_empty() {
            self.suppressions
                .insert(file_path.to_string(), file_suppressions);
        }

        let dead_ranges = compute_dead_code_ranges(source);
        if !dead_ranges.is_empty() {
            self.dead_code_ranges
                .insert(file_path.to_string(), dead_ranges);
        }
    }

    /// Check if a violation should be suppressed.
    ///
    /// Checks inline comment suppressions first, then TOML hash-matched suppressions,
    /// then wildcard suppressions. Returns the justification string if suppressed.
    pub fn should_suppress(
        &self,
        file_path: &str,
        rule_id: &str,
        line: usize,
        source: &str,
        message: &str,
    ) -> Option<&str> {
        // Suppress anything inside a branch that is never compiled when building
        // as C (`#if 0` or a `__cplusplus`-gated C++-only region): any finding
        // there is unfixable noise, since sqc has no preprocessor and would
        // otherwise analyze the inactive branch.
        if let Some(ranges) = self.dead_code_ranges.get(file_path) {
            if ranges
                .iter()
                .any(|&(start, end)| line >= start && line <= end)
            {
                return Some(
                    "code is inside an inactive preprocessor branch (`#if 0` or C++-only \
                     `__cplusplus` block) that is never compiled as C",
                );
            }
        }

        // Check inline comment suppressions
        if let Some(file_supps) = self.suppressions.get(file_path) {
            if let Some(s) = file_supps
                .iter()
                .find(|s| s.rule_id == rule_id && s.matches(source, line))
            {
                return Some(&s.justification);
            }
        }

        // Check TOML hash-matched suppressions (suffix match on file path)
        if let Some(s) = self.toml_suppressions.iter().find_map(|(pattern, s)| {
            if s.rule_id == rule_id
                && file_path_matches(file_path, pattern)
                && s.matches(source, line)
            {
                Some(s)
            } else {
                None
            }
        }) {
            return Some(&s.justification);
        }

        // Check wildcard suppressions
        for w in &self.wildcard_suppressions {
            if w.matches(file_path, rule_id, message) {
                return Some(&w.justification);
            }
        }

        None
    }

    /// Returns the number of wildcard suppressions loaded.
    pub fn wildcard_count(&self) -> usize {
        self.wildcard_suppressions.len()
    }

    /// Calculate hash: SHA-256(rule_id + ":" + whitespace-normalized code), truncated to 16 hex.
    pub fn calculate_suppression_hash(rule_id: &str, code: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(rule_id.as_bytes());
        hasher.update(b":");
        let normalized = code.split_whitespace().collect::<Vec<_>>().join(" ");
        hasher.update(normalized.as_bytes());
        format!("{:x}", hasher.finalize())[..16].to_string()
    }
}

impl CompiledWildcard {
    fn try_from_spec(spec: WildcardSpec) -> Result<Self, String> {
        if spec.file_glob.is_none()
            && spec.rule.is_none()
            && spec.rule_glob.is_none()
            && spec.function_prefix.is_none()
        {
            return Err(
                "wildcard suppression must have at least one of: file_glob (or file), rule, rule_glob, function_prefix".to_string()
            );
        }

        let file_glob = spec
            .file_glob
            .as_deref()
            .map(|g| glob_to_regex(g, true))
            .transpose()?;

        let rule_glob = spec
            .rule_glob
            .as_deref()
            .map(|g| glob_to_regex(g, false))
            .transpose()?;

        Ok(CompiledWildcard {
            file_glob,
            rule: spec.rule,
            rule_glob,
            function_prefix: spec.function_prefix,
            justification: spec.justification,
        })
    }

    fn matches(&self, file_path: &str, rule_id: &str, message: &str) -> bool {
        if let Some(ref re) = self.file_glob {
            let normalized = file_path.replace('\\', "/");
            if !re.is_match(&normalized) {
                return false;
            }
        }

        if let Some(ref rule) = self.rule {
            if rule_id != rule {
                return false;
            }
        }

        if let Some(ref re) = self.rule_glob {
            if !re.is_match(rule_id) {
                return false;
            }
        }

        if let Some(ref prefix) = self.function_prefix {
            if !message_contains_prefix(message, prefix) {
                return false;
            }
        }

        true
    }
}

/// Convert a glob pattern to a compiled regex.
///
/// When `is_path` is true, the pattern matches against file paths:
/// - `**` matches any characters including `/` (zero or more path segments)
/// - `*` matches any characters except `/`
/// - `?` matches any single character except `/`
/// - The pattern is matched as a suffix (preceded by `/` or start of string)
///
/// When `is_path` is false (e.g., rule IDs), `*` and `**` both match any characters.
pub(crate) fn glob_to_regex(pattern: &str, is_path: bool) -> Result<regex::Regex, String> {
    let mut regex_str = String::new();
    let chars: Vec<char> = pattern.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        match chars[i] {
            '*' => {
                if i + 1 < len && chars[i + 1] == '*' {
                    // `**` — match everything (including `/`)
                    regex_str.push_str(".*");
                    i += 2;
                    // Skip trailing `/` after `**` if present
                    if i < len && chars[i] == '/' {
                        regex_str.push_str("/?");
                        i += 1;
                    }
                } else if is_path {
                    // `*` in path mode — match within a single path segment
                    regex_str.push_str("[^/]*");
                    i += 1;
                } else {
                    // `*` in non-path mode — match anything
                    regex_str.push_str(".*");
                    i += 1;
                }
            }
            '?' => {
                if is_path {
                    regex_str.push_str("[^/]");
                } else {
                    regex_str.push('.');
                }
                i += 1;
            }
            c => {
                // Escape regex metacharacters
                if ".()+|[]{}^$\\".contains(c) {
                    regex_str.push('\\');
                }
                regex_str.push(c);
                i += 1;
            }
        }
    }

    // For path patterns, match as suffix (preceded by `/` or start of string)
    let anchored = if is_path {
        format!("(?:^|/){regex_str}$")
    } else {
        format!("^{regex_str}$")
    };

    regex::Regex::new(&anchored).map_err(|e| format!("Invalid glob pattern '{}': {}", pattern, e))
}

/// Check if a violation message contains an identifier starting with the given prefix.
///
/// Looks for the prefix preceded by a non-alphanumeric/underscore character (or start of string),
/// ensuring it matches at a word boundary rather than mid-identifier.
fn message_contains_prefix(message: &str, prefix: &str) -> bool {
    if prefix.is_empty() {
        return false;
    }
    let mut search_from = 0;
    while let Some(pos) = message[search_from..].find(prefix) {
        let abs_pos = search_from + pos;
        // Check that the prefix is at a word boundary (not mid-identifier)
        let at_boundary = abs_pos == 0
            || !message.as_bytes()[abs_pos - 1].is_ascii_alphanumeric()
                && message.as_bytes()[abs_pos - 1] != b'_';
        if at_boundary {
            return true;
        }
        search_from = abs_pos + 1;
    }
    false
}

/// Match a full file path against a TOML suppression file pattern.
///
/// The pattern can be a bare filename (`ringbuffer.c`), a relative path
/// (`src/ringbuffer.c`), or a full path. Matching is by suffix: the full
/// path must end with the pattern, preceded by a path separator or start of string.
fn file_path_matches(full_path: &str, pattern: &str) -> bool {
    if full_path == pattern {
        return true;
    }
    let normalized = full_path.replace('\\', "/");
    let norm_pattern = pattern.replace('\\', "/");
    if normalized.ends_with(&norm_pattern) {
        let prefix_len = normalized.len() - norm_pattern.len();
        prefix_len == 0
            || normalized.as_bytes().get(prefix_len - 1) == Some(&b'/')
            || normalized.as_bytes().get(prefix_len - 1) == Some(&b'\\')
    } else {
        // Also try matching just the filename component
        let file_name = Path::new(full_path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("");
        file_name == pattern
    }
}

/// Which branch of a preprocessor conditional is never compiled when the
/// translation unit is built as C (sqc has no preprocessor, so it would
/// otherwise analyze both branches and flag the inactive one).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BranchKind {
    /// The then-branch is dead in C; the `#else` branch (if any) is live.
    /// Covers `#if 0`, `#ifdef __cplusplus`, `#if defined(__cplusplus)`.
    ThenDead,
    /// The then-branch is live; the `#else` branch is dead in C.
    /// Covers `#ifndef __cplusplus`, `#if !defined(__cplusplus)`.
    ElseDead,
    /// Not a recognized dead-in-C conditional — both branches are analyzed.
    Neutral,
}

/// Leading identifier token of a string (for `#ifdef NAME` / `#ifndef NAME`).
fn first_ident(s: &str) -> &str {
    let s = s.trim_start();
    let end = s
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(s.len());
    &s[..end]
}

/// Classify a `#if` condition's then-branch with respect to `__cplusplus`.
/// `cond` is the text after the `#if` keyword.
fn classify_cpp_if(cond: &str) -> BranchKind {
    let cond = cond.split("//").next().unwrap_or(cond);
    let cond = cond.split("/*").next().unwrap_or(cond);
    let c: String = cond.chars().filter(|ch| !ch.is_whitespace()).collect();
    // A disjunction may be true in C via the non-__cplusplus operand, so we
    // cannot prove either branch dead — stay conservative (analyze both).
    if c.contains("||") || !c.contains("__cplusplus") {
        return BranchKind::Neutral;
    }
    // `&&` chains require every operand, so the polarity of the __cplusplus
    // term decides which branch is dead in C.
    if c.contains("!defined(__cplusplus)") || c.contains("!__cplusplus") {
        BranchKind::ElseDead
    } else {
        // `defined(__cplusplus)`, bare `__cplusplus`, `__cplusplus>=201103L`, …
        BranchKind::ThenDead
    }
}

/// Classify a conditional directive (`if`/`ifdef`/`ifndef`) by which branch is
/// never compiled when building as C.
fn classify_conditional(directive: &str, rest: &str) -> BranchKind {
    match directive {
        "ifdef" => {
            if first_ident(rest) == "__cplusplus" {
                BranchKind::ThenDead
            } else {
                BranchKind::Neutral
            }
        }
        "ifndef" => {
            if first_ident(rest) == "__cplusplus" {
                BranchKind::ElseDead
            } else {
                BranchKind::Neutral
            }
        }
        "if" => {
            if is_zero_condition(rest) {
                BranchKind::ThenDead
            } else {
                classify_cpp_if(rest)
            }
        }
        _ => BranchKind::Neutral,
    }
}

/// Compute the 1-based inclusive line ranges that are never compiled when the
/// file is built as C.
///
/// Covers two families of unconditionally-inactive branches:
///   * `#if 0` / `#if (0)` — literal-zero dead code.
///   * `__cplusplus`-gated C++-only regions — `#ifdef __cplusplus`,
///     `#if defined(__cplusplus) [&& …]` (then-branch dead in C), and the
///     `#else` branch of `#ifndef __cplusplus` / `#if !defined(__cplusplus)`.
///
/// Handles nested conditionals (a nested `#if`/`#ifdef` inside a dead block does
/// not end the block) and ends a dead region at the matching `#else`/`#elif`/
/// `#endif`. This is line-based on purpose: tree-sitter mis-nests these blocks
/// because the C++ `extern "C" {` brace is unbalanced in a C parse.
fn compute_dead_code_ranges(source: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut depth: usize = 0;
    // Kind of each currently-open conditional (parallel to nesting depth), so an
    // `#else` knows whether it opens an else-branch dead region.
    let mut kinds: Vec<BranchKind> = Vec::new();
    // (start_line, conditional-nesting depth at which the dead region opened)
    let mut dead: Option<(usize, usize)> = None;

    for (idx, line) in source.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim_start();
        if !trimmed.starts_with('#') {
            continue;
        }
        let after_hash = trimmed[1..].trim_start();
        let directive: String = after_hash
            .chars()
            .take_while(|c| c.is_ascii_alphabetic())
            .collect();

        match directive.as_str() {
            "if" | "ifdef" | "ifndef" => {
                depth += 1;
                let rest = &after_hash[directive.len()..];
                let kind = classify_conditional(&directive, rest);
                kinds.push(kind);
                if dead.is_none() && kind == BranchKind::ThenDead {
                    dead = Some((line_no, depth));
                }
            }
            "elif" | "else" => {
                if let Some((start, dead_depth)) = dead {
                    if depth == dead_depth {
                        // A dead then-branch ends where its alternative begins.
                        ranges.push((start, line_no));
                        dead = None;
                    }
                } else if directive == "else"
                    && depth > 0
                    && kinds.last() == Some(&BranchKind::ElseDead)
                {
                    // The `#else` branch of `#ifndef __cplusplus` is dead in C.
                    dead = Some((line_no, depth));
                }
            }
            "endif" => {
                if let Some((start, dead_depth)) = dead {
                    if depth == dead_depth {
                        ranges.push((start, line_no));
                        dead = None;
                    }
                }
                kinds.pop();
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }

    // An unterminated dead block (no matching `#endif`) covers the rest of file.
    if let Some((start, _)) = dead {
        let last = source.lines().count().max(start);
        ranges.push((start, last));
    }

    ranges
}

/// Whether a `#if` condition expression is a literal zero (dead branch).
/// Strips trailing comments and surrounding whitespace/parens before comparing.
fn is_zero_condition(cond: &str) -> bool {
    let cond = cond.split("//").next().unwrap_or(cond);
    let cond = cond.split("/*").next().unwrap_or(cond);
    let stripped: String = cond
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '(' && *c != ')')
        .collect();
    stripped == "0"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic() {
        let comment =
            "// SQC-SUPPRESS: ARR30-C HASH:a3f5d2b1 JUSTIFICATION: \"Bounds checked by caller\"";
        let s = Suppression::parse(comment, 0).unwrap();
        assert_eq!(s.rule_id, "ARR30-C");
        assert_eq!(s.hash, "a3f5d2b1");
        assert_eq!(s.justification, "Bounds checked by caller");
        assert_eq!(s.comment_line, 1);
    }

    #[test]
    fn test_parse_no_hash_returns_none() {
        let comment = "// SQC-SUPPRESS: ARR30-C JUSTIFICATION: \"no hash\"";
        assert!(Suppression::parse(comment, 0).is_none());
    }

    #[test]
    fn test_match_line_before() {
        // Suppress comment on line 1, violation on line 2
        let rule_id = "EXP34-C";
        let code_line = "    *ptr = value;";
        let hash = SuppressionManager::calculate_suppression_hash(rule_id, code_line);

        let source = format!(
            "// SQC-SUPPRESS: EXP34-C HASH:{} JUSTIFICATION: \"test\"\n{}",
            hash, code_line
        );

        let s = Suppression::parse(source.lines().next().unwrap(), 0).unwrap();
        assert!(s.matches(&source, 2));
    }

    #[test]
    fn test_match_inline() {
        // Suppress comment inline on the same line as the violation
        let rule_id = "EXP34-C";
        let code_line = "    *ptr = value;";
        let hash = SuppressionManager::calculate_suppression_hash(rule_id, code_line);

        let line_with_suppress = format!(
            "{} // SQC-SUPPRESS: EXP34-C HASH:{} JUSTIFICATION: \"test\"",
            code_line, hash
        );
        let source = format!("int x;\n{}\nint y;", line_with_suppress);

        let s = Suppression::parse(&line_with_suppress, 1).unwrap();
        // Violation on line 2 (same line as the inline suppress comment)
        assert!(s.matches(&source, 2));
    }

    #[test]
    fn test_match_stacked() {
        // Two suppress comments before one code line
        let code_line = "    bytes_read = fread(buf, 1, file_size, fp);";
        let hash_err = SuppressionManager::calculate_suppression_hash("ERR00-C", code_line);
        let hash_exp = SuppressionManager::calculate_suppression_hash("EXP34-C", code_line);

        let source = format!(
            "// SQC-SUPPRESS: ERR00-C HASH:{} JUSTIFICATION: \"r1\"\n\
             // SQC-SUPPRESS: EXP34-C HASH:{} JUSTIFICATION: \"r2\"\n\
             {}",
            hash_err, hash_exp, code_line
        );

        let mut lines = source.lines();
        let s1 = Suppression::parse(lines.next().unwrap(), 0).unwrap();
        let s2 = Suppression::parse(lines.next().unwrap(), 1).unwrap();

        // Both should match violations on line 3
        assert!(s1.matches(&source, 3));
        assert!(s2.matches(&source, 3));
    }

    #[test]
    fn test_no_match_wrong_rule() {
        let code_line = "    *ptr = value;";
        let hash = SuppressionManager::calculate_suppression_hash("INT30-C", code_line);

        let source = format!(
            "// SQC-SUPPRESS: INT30-C HASH:{} JUSTIFICATION: \"test\"\n{}",
            hash, code_line
        );

        let s = Suppression::parse(source.lines().next().unwrap(), 0).unwrap();
        // Rule ID won't match at the should_suppress level, but matches() only checks hash
        assert!(s.matches(&source, 2));
    }

    #[test]
    fn test_no_match_too_far() {
        let code_line = "    *ptr = value;";
        let hash = SuppressionManager::calculate_suppression_hash("EXP34-C", code_line);

        // Comment on line 1, violation on line 20 — too far
        let mut lines = vec![format!(
            "// SQC-SUPPRESS: EXP34-C HASH:{} JUSTIFICATION: \"test\"",
            hash
        )];
        for _ in 0..18 {
            lines.push("// filler".to_string());
        }
        lines.push(code_line.to_string());
        let source = lines.join("\n");

        let s = Suppression::parse(source.lines().next().unwrap(), 0).unwrap();
        assert!(!s.matches(&source, 20));
    }

    #[test]
    fn test_no_match_code_changed() {
        let original_code = "    *ptr = value;";
        let hash = SuppressionManager::calculate_suppression_hash("EXP34-C", original_code);

        // Code has been modified since hash was generated
        let modified_source = format!(
            "// SQC-SUPPRESS: EXP34-C HASH:{} JUSTIFICATION: \"test\"\n    *ptr = new_value;",
            hash
        );

        let s = Suppression::parse(modified_source.lines().next().unwrap(), 0).unwrap();
        assert!(!s.matches(&modified_source, 2));
    }

    #[test]
    fn test_strip_suppress_comment() {
        let line = "    *ptr = val; // SQC-SUPPRESS: EXP34-C HASH:abc JUSTIFICATION: \"test\"";
        let stripped = Suppression::strip_suppress_comment(line);
        assert_eq!(stripped, "    *ptr = val; ");
    }

    #[test]
    fn test_manager_roundtrip() {
        let rule_id = "EXP34-C";
        let code_line = "    *ptr = value;";
        let hash = SuppressionManager::calculate_suppression_hash(rule_id, code_line);

        let source = format!(
            "void f(int *ptr) {{\n\
             // SQC-SUPPRESS: EXP34-C HASH:{} JUSTIFICATION: \"validated by caller\"\n\
             {}\n\
             }}",
            hash, code_line
        );

        let mut mgr = SuppressionManager::new();
        mgr.extract_from_source("test.c", &source);

        // Should suppress EXP34-C on line 3
        assert!(mgr
            .should_suppress("test.c", "EXP34-C", 3, &source, "")
            .is_some());

        // Should NOT suppress different rule
        assert!(mgr
            .should_suppress("test.c", "INT30-C", 3, &source, "")
            .is_none());

        // Should NOT suppress different file
        assert!(mgr
            .should_suppress("other.c", "EXP34-C", 3, &source, "")
            .is_none());
    }

    #[test]
    fn test_unified_syntax_suppresses_violation() {
        let rule_id = "EXP34-C";
        let code_line = "    *ptr = value;";
        let hash = SuppressionManager::calculate_suppression_hash(rule_id, code_line);

        let source = format!(
            "void f(int *ptr) {{\n\
             // tools:suppress sqc:{} HASH:{} JUSTIFICATION:\"validated by caller\"\n\
             {}\n\
             }}",
            rule_id, hash, code_line
        );

        let mut mgr = SuppressionManager::new();
        mgr.extract_from_source("test.c", &source);

        assert!(mgr
            .should_suppress("test.c", "EXP34-C", 3, &source, "")
            .is_some());
        assert!(mgr
            .should_suppress("test.c", "INT30-C", 3, &source, "")
            .is_none());
    }

    #[test]
    fn test_unified_syntax_requires_hash() {
        let source = "// tools:suppress sqc:EXP34-C JUSTIFICATION:\"no hash\"\n    *ptr = value;\n";
        let mut mgr = SuppressionManager::new();
        mgr.extract_from_source("test.c", source);
        assert!(mgr
            .should_suppress("test.c", "EXP34-C", 2, source, "")
            .is_none());
    }

    #[test]
    fn test_unified_syntax_ignores_other_tools() {
        let source = "// tools:suppress knots:cognitive JUSTIFICATION:\"legacy\"\nvoid f() {}\n";
        let mut mgr = SuppressionManager::new();
        mgr.extract_from_source("test.c", source);
        assert!(mgr
            .should_suppress("test.c", "cognitive", 2, source, "")
            .is_none());
    }

    #[test]
    fn test_legacy_and_unified_syntax_coexist() {
        let hash_legacy =
            SuppressionManager::calculate_suppression_hash("EXP34-C", "    *ptr = value;");
        let hash_unified =
            SuppressionManager::calculate_suppression_hash("INT30-C", "    result = a + b;");
        let source = format!(
            "// SQC-SUPPRESS: EXP34-C HASH:{} JUSTIFICATION: \"legacy\"\n\
             *ptr = value;\n\
             // tools:suppress sqc:INT30-C HASH:{} JUSTIFICATION:\"unified\"\n\
             result = a + b;\n",
            hash_legacy, hash_unified
        );

        let mut mgr = SuppressionManager::new();
        mgr.extract_from_source("test.c", &source);

        assert!(mgr
            .should_suppress("test.c", "EXP34-C", 2, &source, "")
            .is_some());
        assert!(mgr
            .should_suppress("test.c", "INT30-C", 4, &source, "")
            .is_some());
    }

    #[test]
    fn test_file_path_matches_bare_filename() {
        assert!(file_path_matches(
            "/home/user/project/src/ringbuffer.c",
            "ringbuffer.c"
        ));
        assert!(file_path_matches("ringbuffer.c", "ringbuffer.c"));
        assert!(!file_path_matches(
            "/home/user/project/src/other.c",
            "ringbuffer.c"
        ));
    }

    #[test]
    fn test_file_path_matches_relative_path() {
        assert!(file_path_matches(
            "/home/user/project/src/ringbuffer.c",
            "src/ringbuffer.c"
        ));
        assert!(!file_path_matches(
            "/home/user/project/lib/ringbuffer.c",
            "src/ringbuffer.c"
        ));
    }

    #[test]
    fn test_toml_suppression() {
        let rule_id = "INT30-C";
        let code_line = "    result = a + b;";
        let hash = SuppressionManager::calculate_suppression_hash(rule_id, code_line);

        // Build source: violation on line 5
        let source = format!(
            "void f() {{\n  int a = 1;\n  int b = 2;\n  unsigned result;\n{}\n}}",
            code_line
        );

        let mut mgr = SuppressionManager::new();
        // Add a TOML-sourced suppression (comment_line = 0)
        mgr.toml_suppressions.push((
            "test.c".to_string(),
            Suppression {
                rule_id: rule_id.to_string(),
                hash,
                justification: "overflow checked".to_string(),
                comment_line: 0,
            },
        ));

        // Should match via TOML (no proximity check, suffix match on filename)
        assert!(mgr
            .should_suppress("/some/path/test.c", rule_id, 5, &source, "")
            .is_some());

        // Should NOT match different file
        assert!(mgr
            .should_suppress("/some/path/other.c", rule_id, 5, &source, "")
            .is_none());
    }

    #[test]
    fn test_inline_and_toml_coexist() {
        // Inline suppresses one rule, TOML suppresses a different rule on the same file
        let code_line = "    result = *ptr + offset;";
        let hash_exp = SuppressionManager::calculate_suppression_hash("EXP34-C", code_line);
        let hash_int = SuppressionManager::calculate_suppression_hash("INT30-C", code_line);

        // Source has an inline suppression for EXP34-C on line 2
        let source = format!(
            "// SQC-SUPPRESS: EXP34-C HASH:{} JUSTIFICATION: \"ptr checked\"\n{}",
            hash_exp, code_line
        );

        let mut mgr = SuppressionManager::new();
        mgr.extract_from_source("/project/test.c", &source);

        // Add TOML suppression for INT30-C on the same file
        mgr.toml_suppressions.push((
            "test.c".to_string(),
            Suppression {
                rule_id: "INT30-C".to_string(),
                hash: hash_int,
                justification: "overflow checked".to_string(),
                comment_line: 0,
            },
        ));

        // EXP34-C suppressed by inline comment
        assert!(mgr
            .should_suppress("/project/test.c", "EXP34-C", 2, &source, "")
            .is_some());

        // INT30-C suppressed by TOML entry
        assert!(mgr
            .should_suppress("/project/test.c", "INT30-C", 2, &source, "")
            .is_some());

        // ARR30-C not suppressed by either
        assert!(mgr
            .should_suppress("/project/test.c", "ARR30-C", 2, &source, "")
            .is_none());
    }

    #[test]
    fn test_inline_detection() {
        // Ensure extract_from_source finds inline suppress comments (not just standalone)
        let code_line = "    free(ptr);";
        let hash = SuppressionManager::calculate_suppression_hash("EXP34-C", code_line);

        let source = format!(
            "void f(void *ptr) {{\n\
             {} // SQC-SUPPRESS: EXP34-C HASH:{} JUSTIFICATION: \"NULL is valid\"\n\
             }}",
            code_line, hash
        );

        let mut mgr = SuppressionManager::new();
        mgr.extract_from_source("test.c", &source);

        assert!(mgr
            .should_suppress("test.c", "EXP34-C", 2, &source, "")
            .is_some());
    }

    // --- Glob pattern matching tests ---

    #[test]
    fn test_glob_to_regex_simple_star() {
        let re = glob_to_regex("*.c", true).unwrap();
        assert!(re.is_match("test.c"));
        assert!(re.is_match("/project/src/test.c"));
        assert!(!re.is_match("test.h"));
        // *.c matches any .c file (suffix match at path boundary)
        assert!(re.is_match("/project/src/sub/test.c"));
        // But * doesn't cross / — so "sub/*.c" won't match nested paths
        let re2 = glob_to_regex("sub/*.c", true).unwrap();
        assert!(re2.is_match("/project/sub/test.c"));
        assert!(!re2.is_match("/project/sub/deep/test.c"));
    }

    #[test]
    fn test_glob_to_regex_double_star() {
        let re = glob_to_regex("src/vendor/**", true).unwrap();
        assert!(re.is_match("src/vendor/lib.c"));
        assert!(re.is_match("src/vendor/sub/deep/lib.c"));
        assert!(re.is_match("/project/src/vendor/lib.c"));
        assert!(!re.is_match("src/other/lib.c"));
    }

    #[test]
    fn test_glob_to_regex_double_star_prefix() {
        let re = glob_to_regex("**/*.generated.c", true).unwrap();
        assert!(re.is_match("src/foo.generated.c"));
        assert!(re.is_match("/a/b/c/foo.generated.c"));
        assert!(!re.is_match("src/foo.c"));
    }

    #[test]
    fn test_glob_to_regex_question_mark() {
        let re = glob_to_regex("test?.c", true).unwrap();
        assert!(re.is_match("test1.c"));
        assert!(re.is_match("/project/testA.c"));
        assert!(!re.is_match("test.c")); // ? requires exactly one char
        assert!(!re.is_match("test12.c")); // ? is only one char
    }

    #[test]
    fn test_glob_to_regex_rule_pattern() {
        let re = glob_to_regex("DCL*", false).unwrap();
        assert!(re.is_match("DCL31-C"));
        assert!(re.is_match("DCL07-C"));
        assert!(!re.is_match("INT30-C"));
    }

    #[test]
    fn test_glob_to_regex_rule_exact() {
        let re = glob_to_regex("INT3?-C", false).unwrap();
        assert!(re.is_match("INT30-C"));
        assert!(re.is_match("INT32-C"));
        assert!(!re.is_match("INT300-C"));
    }

    // --- Message prefix matching tests ---

    #[test]
    fn test_message_contains_prefix_basic() {
        let msg = "Function 'wolfSSL_Init' is called without prior declaration";
        assert!(message_contains_prefix(msg, "wolfSSL_"));
        assert!(!message_contains_prefix(msg, "openSSL_"));
    }

    #[test]
    fn test_message_contains_prefix_word_boundary() {
        let msg = "Function 'myWolfSSL_Init' is called without prior declaration";
        // "wolfSSL_" appears inside "myWolfSSL_Init" but not at a word boundary
        assert!(!message_contains_prefix(msg, "wolfSSL_"));
    }

    #[test]
    fn test_message_contains_prefix_at_start() {
        let msg = "wolfSSL_Init is undeclared";
        assert!(message_contains_prefix(msg, "wolfSSL_"));
    }

    #[test]
    fn test_message_contains_prefix_after_quote() {
        let msg = "Use of undeclared function 'cJSON_Parse'";
        assert!(message_contains_prefix(msg, "cJSON_"));
    }

    #[test]
    fn test_message_contains_prefix_empty() {
        assert!(!message_contains_prefix("anything", ""));
    }

    // --- Wildcard suppression integration tests ---

    #[test]
    fn test_wildcard_file_glob() {
        let mut mgr = SuppressionManager::new();
        mgr.wildcard_suppressions.push(
            CompiledWildcard::try_from_spec(WildcardSpec {
                file_glob: Some("src/vendor/**".to_string()),
                rule: Some("DCL31-C".to_string()),
                rule_glob: None,
                function_prefix: None,
                justification: "Vendor code".to_string(),
            })
            .unwrap(),
        );

        // Matches: vendor file + correct rule
        assert!(mgr
            .should_suppress(
                "/project/src/vendor/lib.c",
                "DCL31-C",
                10,
                "",
                "Function 'foo' is called without prior declaration",
            )
            .is_some());

        // No match: wrong directory
        assert!(mgr
            .should_suppress(
                "/project/src/core/lib.c",
                "DCL31-C",
                10,
                "",
                "Function 'foo' is called without prior declaration",
            )
            .is_none());

        // No match: wrong rule
        assert!(mgr
            .should_suppress(
                "/project/src/vendor/lib.c",
                "INT30-C",
                10,
                "",
                "Unsigned overflow",
            )
            .is_none());
    }

    #[test]
    fn test_wildcard_rule_glob() {
        let mut mgr = SuppressionManager::new();
        mgr.wildcard_suppressions.push(
            CompiledWildcard::try_from_spec(WildcardSpec {
                file_glob: Some("vendor/**".to_string()),
                rule: None,
                rule_glob: Some("DCL*".to_string()),
                function_prefix: None,
                justification: "All DCL rules suppressed for vendor".to_string(),
            })
            .unwrap(),
        );

        // Matches: vendor file + DCL rule
        assert!(mgr
            .should_suppress("/project/vendor/lib.c", "DCL31-C", 10, "", "")
            .is_some());
        assert!(mgr
            .should_suppress("/project/vendor/lib.c", "DCL07-C", 10, "", "")
            .is_some());

        // No match: non-DCL rule
        assert!(mgr
            .should_suppress("/project/vendor/lib.c", "INT30-C", 10, "", "")
            .is_none());
    }

    #[test]
    fn test_wildcard_function_prefix() {
        let mut mgr = SuppressionManager::new();
        mgr.wildcard_suppressions.push(
            CompiledWildcard::try_from_spec(WildcardSpec {
                file_glob: None,
                rule: Some("DCL31-C".to_string()),
                rule_glob: None,
                function_prefix: Some("wolfSSL_".to_string()),
                justification: "wolfSSL library functions".to_string(),
            })
            .unwrap(),
        );

        // Matches: DCL31-C with wolfSSL_ function in message
        assert!(mgr
            .should_suppress(
                "any_file.c",
                "DCL31-C",
                10,
                "",
                "Function 'wolfSSL_Init' is called without prior declaration",
            )
            .is_some());

        // No match: different function prefix
        assert!(mgr
            .should_suppress(
                "any_file.c",
                "DCL31-C",
                10,
                "",
                "Function 'openSSL_Init' is called without prior declaration",
            )
            .is_none());

        // No match: wrong rule even with matching prefix
        assert!(mgr
            .should_suppress("any_file.c", "INT30-C", 10, "", "wolfSSL_Init overflow",)
            .is_none());
    }

    #[test]
    fn test_wildcard_justification_returned() {
        let mut mgr = SuppressionManager::new();
        mgr.wildcard_suppressions.push(
            CompiledWildcard::try_from_spec(WildcardSpec {
                file_glob: Some("**".to_string()),
                rule: Some("DCL31-C".to_string()),
                rule_glob: None,
                function_prefix: None,
                justification: "Global DCL31-C suppression".to_string(),
            })
            .unwrap(),
        );

        let result = mgr.should_suppress("any.c", "DCL31-C", 1, "", "");
        assert_eq!(result, Some("Global DCL31-C suppression"));
    }

    #[test]
    fn test_wildcard_requires_at_least_one_field() {
        let result = CompiledWildcard::try_from_spec(WildcardSpec {
            file_glob: None,
            rule: None,
            rule_glob: None,
            function_prefix: None,
            justification: "No filters".to_string(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_wildcard_toml_parsing() {
        let toml_str = r#"
[[suppress]]
name = "vendor-dcl31"
tool = "sqc"
file_glob = "src/vendor/**"
rule = "DCL31-C"
justification = "Vendor code"

[[suppress]]
name = "wolfssl-dcl"
tool = "sqc"
rule_glob = "DCL*"
function_prefix = "wolfSSL_"
justification = "wolfSSL library"
"#;
        let parsed: SuppressFile = toml::from_str(toml_str).unwrap();
        assert_eq!(parsed.suppress.len(), 2);
        assert_eq!(
            parsed.suppress[0].file_glob.as_deref(),
            Some("src/vendor/**")
        );
        assert_eq!(parsed.suppress[0].rule.as_deref(), Some("DCL31-C"));
        assert_eq!(parsed.suppress[1].rule_glob.as_deref(), Some("DCL*"));
        assert_eq!(
            parsed.suppress[1].function_prefix.as_deref(),
            Some("wolfSSL_")
        );
    }

    #[test]
    fn test_wildcard_and_hash_coexist_in_toml() {
        let toml_str = r#"
[[suppress]]
name = "ringbuffer-int30"
tool = "sqc"
file = "ringbuffer.c"
rule = "INT30-C"
hash = "a1f5861150a1e5b8"
justification = "Hash-matched suppression"

[[suppress]]
name = "vendor-dcl31"
tool = "sqc"
file_glob = "src/vendor/**"
rule = "DCL31-C"
justification = "Wildcard suppression"
"#;
        let parsed: SuppressFile = toml::from_str(toml_str).unwrap();
        assert_eq!(parsed.suppress.len(), 2);
        assert!(parsed.suppress[0].hash.is_some());
        assert!(parsed.suppress[1].hash.is_none());
    }

    #[test]
    fn test_suppress_toml_ignores_other_tools() {
        let mut mgr = SuppressionManager::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("suppress.toml");
        std::fs::write(
            &path,
            r#"
[[suppress]]
name = "knots-only"
tool = "knots"
rule_glob = "*"
justification = "not sqc"

[[suppress]]
name = "sqc-wildcard"
tool = "sqc"
rule_glob = "DCL*"
justification = "sqc wildcard"
"#,
        )
        .unwrap();
        let count = mgr.load_from_toml(path.to_str().unwrap()).unwrap();
        assert_eq!(count, 1);
        assert!(mgr.should_suppress("any.c", "DCL31-C", 1, "", "").is_some());
    }

    #[test]
    fn test_suppress_toml_wildcard_tool_applies() {
        let mut mgr = SuppressionManager::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("suppress.toml");
        std::fs::write(
            &path,
            r#"
[[suppress]]
name = "third-party"
tool = "*"
file_glob = "third_party/**"
justification = "Third-party code"
"#,
        )
        .unwrap();
        mgr.load_from_toml(path.to_str().unwrap()).unwrap();
        assert!(mgr
            .should_suppress("third_party/lib.c", "INT30-C", 1, "", "")
            .is_some());
    }

    #[test]
    fn test_hash_suppression_takes_priority_over_wildcard() {
        let rule_id = "EXP34-C";
        let code_line = "    *ptr = value;";
        let hash = SuppressionManager::calculate_suppression_hash(rule_id, code_line);

        let source = format!(
            "// SQC-SUPPRESS: EXP34-C HASH:{} JUSTIFICATION: \"inline justification\"\n{}",
            hash, code_line
        );

        let mut mgr = SuppressionManager::new();
        mgr.extract_from_source("test.c", &source);
        mgr.wildcard_suppressions.push(
            CompiledWildcard::try_from_spec(WildcardSpec {
                file_glob: Some("**".to_string()),
                rule: Some("EXP34-C".to_string()),
                rule_glob: None,
                function_prefix: None,
                justification: "wildcard justification".to_string(),
            })
            .unwrap(),
        );

        // Inline hash suppression should match first (returns inline justification)
        let result = mgr.should_suppress("test.c", "EXP34-C", 2, &source, "");
        assert_eq!(result, Some("inline justification"));
    }

    #[test]
    fn test_dead_code_simple_if0() {
        let source = "int a;\n#if 0\nint dead;\nint dead2;\n#endif\nint b;\n";
        let ranges = compute_dead_code_ranges(source);
        // `#if 0` on line 2 through `#endif` on line 5 inclusive.
        assert_eq!(ranges, vec![(2, 5)]);
    }

    #[test]
    fn test_dead_code_ends_at_else() {
        // For `#if 0`, the `#else` branch IS compiled, so the dead region stops there.
        let source = "#if 0\ndead;\n#else\nlive;\n#endif\n";
        let ranges = compute_dead_code_ranges(source);
        assert_eq!(ranges, vec![(1, 3)]);
    }

    #[test]
    fn test_dead_code_nested_conditional() {
        // A nested `#if 1` inside `#if 0` must not terminate the outer dead block.
        let source = "#if 0\n#if 1\nstill_dead;\n#endif\nalso_dead;\n#endif\nlive;\n";
        let ranges = compute_dead_code_ranges(source);
        assert_eq!(ranges, vec![(1, 6)]);
    }

    #[test]
    fn test_dead_code_paren_zero() {
        let source = "#if (0)\ndead;\n#endif\n";
        assert_eq!(compute_dead_code_ranges(source), vec![(1, 3)]);
        // A non-zero condition is not dead.
        assert!(compute_dead_code_ranges("#if 1\nx;\n#endif\n").is_empty());
        assert!(compute_dead_code_ranges("#if defined(X)\nx;\n#endif\n").is_empty());
    }

    #[test]
    fn test_dead_code_ifdef_cplusplus() {
        // `#ifdef __cplusplus` then-branch is dead when compiling as C.
        let source = "#ifdef __cplusplus\nextern \"C\" {\n#endif\nint live(void);\n";
        // Dead region is lines 1..=3 (the directive, the C++ line, the #endif).
        assert_eq!(compute_dead_code_ranges(source), vec![(1, 3)]);
    }

    #[test]
    fn test_dead_code_if_defined_cplusplus_and() {
        // raylib/raymath operator block: `#if defined(__cplusplus) && !defined(X)`.
        let source =
            "#if defined(__cplusplus) && !defined(RAYMATH_DISABLE_CPP_OPERATORS)\nop();\n#endif\n";
        assert_eq!(compute_dead_code_ranges(source), vec![(1, 3)]);
    }

    #[test]
    fn test_dead_code_ifndef_cplusplus_else_is_dead() {
        // `#ifndef __cplusplus`: then-branch is live (C), the `#else` is C++ dead.
        let source = "#ifndef __cplusplus\nc_code();\n#else\ncpp_code();\n#endif\n";
        // Only the `#else`..`#endif` span (lines 3..=5) is dead.
        assert_eq!(compute_dead_code_ranges(source), vec![(3, 5)]);
    }

    #[test]
    fn test_dead_code_cplusplus_negation_not_dead_in_c() {
        // `#if !defined(__cplusplus)` then-branch is the C branch — live, not dead.
        let source = "#if !defined(__cplusplus)\nc_code();\n#endif\n";
        assert!(compute_dead_code_ranges(source).is_empty());
    }

    #[test]
    fn test_dead_code_cplusplus_disjunction_conservative() {
        // A disjunction can be true in C, so neither branch is provably dead.
        let source = "#if defined(__cplusplus) || defined(FORCE)\nx();\n#endif\n";
        assert!(compute_dead_code_ranges(source).is_empty());
    }

    #[test]
    fn test_dead_code_extern_c_wrapper_keeps_middle_live() {
        // The classic header shape: two separate `#ifdef __cplusplus` guards
        // around `extern "C" {` / `}` must NOT suppress the C code between them.
        let source = "#ifdef __cplusplus\nextern \"C\" {\n#endif\n\
                      int real_c_code(int x);\n\
                      #ifdef __cplusplus\n}\n#endif\n";
        let ranges = compute_dead_code_ranges(source);
        // Line 4 (real_c_code) must be live.
        assert!(!ranges.iter().any(|&(s, e)| 4 >= s && 4 <= e));
        // The two guard regions are dead.
        assert!(ranges.iter().any(|&(s, e)| 2 >= s && 2 <= e));
        assert!(ranges.iter().any(|&(s, e)| 6 >= s && 6 <= e));
    }

    #[test]
    fn test_should_suppress_dead_code() {
        let mut mgr = SuppressionManager::new();
        let source = "int a;\n#if 0\nbad_thing();\n#endif\nint b;\n";
        mgr.extract_from_source("test.c", source);

        // A violation reported on the dead line is suppressed.
        let result = mgr.should_suppress("test.c", "MEM30-C", 3, source, "");
        assert!(result.is_some());
        // A violation outside the block is not.
        assert_eq!(
            mgr.should_suppress("test.c", "MEM30-C", 5, source, ""),
            None
        );
    }
}
