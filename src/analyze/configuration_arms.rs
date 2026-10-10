//! Which lines of a file the build configuration compiles
//! (`docs/design/generated-headers-and-configuration.md` §4.2, M2).
//!
//! A file the configuration compiles still holds arms it does not:
//! `#ifdef CONFIG_VTX` in a build without VT-x, the whole body of an
//! SMP-only file in a uniprocessor build. A build-generated header's facts
//! describe the configuration, so they apply to the arms it compiles and to
//! nothing else. This module decides, line by line, which arms those are:
//! the configuration's macro state is the database's `-D`/`-U`, the
//! definitions in its generated headers, and the definitions the project's
//! own headers derive from those (`#ifdef CONFIG_ENABLE_SMP_SUPPORT` /
//! `#define ENABLE_SMP_SUPPORT`), and a name none of them defines is
//! undefined, as it is for the compiler. Only an identifier reserved to the
//! implementation (`__GNUC__`, `_WIN32`), which the compiler may predefine,
//! is unknown unless the database defines it.
//!
//! A line is *compiled* when every arm enclosing it is taken under that
//! state, *excluded* when one is not, and *unknown* when the state cannot
//! decide (a reserved name, a function-like macro in a condition, a value
//! that is not an integer). Only a compiled line sees generated facts; an
//! unknown one is treated as excluded, the conservative choice, as if the
//! headers were missing. This decides which facts a line resolves names
//! with, never whether a finding is emitted (ADR-0010 D3).

use std::collections::HashMap;
use std::path::Path;

use super::compile_commands::CompileDb;

/// A three-valued preprocessor value: a known integer, or unknown.
type Val = Option<i64>;

/// What a name is bound to at some point of a configuration. Joined in
/// the order undefined, a value, no known value, unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Binding {
    /// Defined, with its integer value when it has one.
    Defined(Option<i64>),
    /// Undefined (`#undef`).
    Undefined,
    /// Defined or undefined under an arm the state cannot decide, or bound
    /// differently by headers whose order the state does not know.
    Unknown,
}

impl Binding {
    /// The binding a name has when two headers, read in no known order,
    /// leave it as `self` and `other`: agreeing bindings stand, two
    /// definitions with different values leave it defined with no known
    /// value, and anything else could be either.
    fn join(self, other: Binding) -> Binding {
        match (self, other) {
            (a, b) if a == b => a,
            (Binding::Defined(_), Binding::Defined(_)) => Binding::Defined(None),
            _ => Binding::Unknown,
        }
    }
}

/// The most rounds [`ConfigState::build`] reads one set of headers for.
/// Real configurations settle in two or three, a chain of headers each
/// deriving a name from the one before in one round per link.
const MAX_ROUNDS: usize = 16;

/// The configuration's macro state: every name it defines, with its integer
/// value when it has one, and the names it cannot decide. A name absent from
/// it is undefined.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConfigState {
    names: HashMap<String, Binding>,
}

/// A source of macro state, for reading a file under it.
trait Macros {
    /// What `name` is bound to, or `None` when nothing binds it.
    fn binding(&self, name: &str) -> Option<Binding>;
}

impl Macros for ConfigState {
    fn binding(&self, name: &str) -> Option<Binding> {
        self.names.get(name).copied()
    }
}

/// What each header bound in one round: name -> (header index, binding).
type Round = HashMap<String, Vec<(usize, Binding)>>;

/// The state one header is read under in a round: the fixed `base`, then
/// what the OTHER headers bound in the previous round. Never its own: a
/// header is read once, so `#ifndef X` / `#define X` must not see the X it
/// defines itself.
struct Others<'a> {
    base: &'a HashMap<String, Binding>,
    round: &'a Round,
    me: usize,
}

impl Macros for Others<'_> {
    fn binding(&self, name: &str) -> Option<Binding> {
        if let Some(b) = self.base.get(name) {
            return Some(*b);
        }
        self.round
            .get(name)?
            .iter()
            .filter(|(header, _)| *header != self.me)
            .map(|(_, b)| *b)
            .reduce(Binding::join)
    }
}

impl ConfigState {
    /// The state of `db`'s configuration: its `-D` flags, then the
    /// definitions in its `generated` headers, then those in `headers` (the
    /// project headers the configuration's files reach), read under the
    /// generated headers' as a build's own headers are.
    ///
    /// Each set is read in rounds. In a round every header is read under the
    /// fixed state so far plus what the other headers bound in the previous
    /// round, never its own, and the round's bindings replace the previous
    /// round's; reading stops when a round binds what the one before did.
    /// So a header sees what every other header defines, as if each included
    /// what it depends on first: `#ifndef CONFIG_SMP` / `#define UP_ONLY`
    /// binds nothing once the generated header defines `CONFIG_SMP`, and
    /// `#ifndef X` / `#define X` defines `X`. Headers that bind one name
    /// differently leave it defined with no known value, or unknown, so the
    /// order they are read in cannot matter. A name still changing when the
    /// rounds run out, and every name a header binds under a condition on
    /// one, is unknown (two headers that each define `X` unless it is
    /// defined never settle). A header's include guard is taken as open, as
    /// on its first inclusion, and its `#define` is recorded like any other,
    /// as the compiler holds it after the inclusion. A header that undefines
    /// a name the command line or a generated header defines, or binds it
    /// under an arm the state cannot decide, leaves it unknown.
    pub fn build<'a>(
        db: Option<&CompileDb>,
        generated: impl IntoIterator<Item = &'a Path>,
        headers: impl IntoIterator<Item = &'a Path>,
    ) -> Self {
        let mut base: HashMap<String, Binding> = HashMap::new();
        if let Some(db) = db {
            for d in &db.defines {
                // A bare -DFOO defines FOO as 1.
                let value = if d.body.trim().is_empty() {
                    Some(1)
                } else {
                    int_value(&d.body)
                };
                base.insert(d.name().to_string(), Binding::Defined(value));
            }
        }
        let read = |paths: Vec<&Path>| -> Vec<String> {
            let mut paths = paths;
            paths.sort();
            paths.dedup();
            paths
                .into_iter()
                .filter_map(|p| std::fs::read_to_string(p).ok())
                .collect()
        };
        let generated: Vec<&Path> = generated.into_iter().collect();
        let headers: Vec<&Path> = headers
            .into_iter()
            .filter(|h| !generated.contains(h))
            .collect();
        // The generated headers' definitions stand for the project's, as the
        // command line's stand for both.
        let generated_names = settle(&base, &read(generated));
        base.extend(generated_names);
        let project_names = settle(&base, &read(headers));
        base.extend(project_names);
        ConfigState { names: base }
    }
}

/// What `texts` bind when read in rounds over the fixed `base`
/// ([`ConfigState::build`]); a name in `base` stands.
fn settle(base: &HashMap<String, Binding>, texts: &[String]) -> HashMap<String, Binding> {
    let mut rounds: Vec<Round> = vec![Round::new()];
    let mut depends: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    // A fixed name a header may undefine: which holds after the header is
    // read depends on whether it is.
    let mut contested: std::collections::HashSet<String> = std::collections::HashSet::new();
    for _ in 0..MAX_ROUNDS {
        let prev = rounds.last().expect("seeded");
        let mut next = Round::new();
        contested.clear();
        for (me, text) in texts.iter().enumerate() {
            let view = Others {
                base,
                round: prev,
                me,
            };
            let scanned = scan(text, &view, true);
            for (name, binding) in scanned.bindings {
                if !base.contains_key(&name) {
                    next.entry(name).or_default().push((me, binding));
                } else if matches!(binding, Binding::Undefined | Binding::Unknown) {
                    contested.insert(name);
                }
            }
            for (name, on) in scanned.depends {
                depends.entry(name).or_default().extend(on);
            }
        }
        let settled = &next == prev;
        rounds.push(next);
        if settled {
            let mut out = joined(rounds.last().expect("pushed"));
            out.extend(contested.into_iter().map(|n| (n, Binding::Unknown)));
            return out;
        }
    }
    // Not settled: every name bound differently by the later rounds is
    // unknown, and so is every name a header binds under a condition on
    // an unknown one, however many links away (a chain longer than the
    // rounds has links the rounds never reached).
    let later: Vec<HashMap<String, Binding>> =
        rounds[rounds.len() / 2..].iter().map(joined).collect();
    let mut out = later.last().cloned().unwrap_or_default();
    let mut unknown: Vec<String> = later
        .iter()
        .flat_map(|r| r.keys())
        .filter(|n| later.iter().any(|r| r.get(*n) != later[0].get(*n)))
        .cloned()
        .collect();
    let mut seen: std::collections::HashSet<String> = unknown.iter().cloned().collect();
    while let Some(name) = unknown.pop() {
        out.insert(name.clone(), Binding::Unknown);
        for (dependent, on) in &depends {
            if on.contains(&name) && !base.contains_key(dependent) && seen.insert(dependent.clone())
            {
                unknown.push(dependent.clone());
            }
        }
    }
    out.extend(contested.into_iter().map(|n| (n, Binding::Unknown)));
    out
}

/// A round's bindings joined across its headers; a name only undefined is
/// left out.
fn joined(round: &Round) -> HashMap<String, Binding> {
    round
        .iter()
        .filter_map(|(name, bound)| {
            let b = bound.iter().map(|(_, b)| *b).reduce(Binding::join)?;
            (b != Binding::Undefined).then(|| (name.clone(), b))
        })
        .collect()
}

/// `name` as `macros` bind it; an implementation-reserved name nothing
/// binds is unknown, any other is undefined.
fn lookup(macros: &dyn Macros, name: &str) -> Lookup {
    match macros.binding(name) {
        Some(Binding::Defined(v)) => Lookup::Defined(v),
        Some(Binding::Unknown) => Lookup::Unknown,
        Some(Binding::Undefined) => Lookup::Undefined,
        None if is_reserved(name) => Lookup::Unknown,
        None => Lookup::Undefined,
    }
}

/// The state as a file sees it from a given line: the configuration's,
/// with the file's own `#define`s and `#undef`s so far on top, kept apart so
/// that reading a header never copies the whole state.
struct View<'a> {
    base: &'a dyn Macros,
    local: HashMap<String, Binding>,
}

impl View<'_> {
    fn value_of(&self, name: &str) -> Lookup {
        match self.local.get(name) {
            Some(Binding::Defined(v)) => Lookup::Defined(*v),
            Some(Binding::Undefined) => Lookup::Undefined,
            Some(Binding::Unknown) => Lookup::Unknown,
            None => lookup(self.base, name),
        }
    }
}

enum Lookup {
    Defined(Option<i64>),
    Undefined,
    Unknown,
}

/// Whether every line of `source` the configuration compiles is told apart:
/// `true` at a line every enclosing arm of which is taken under `state`,
/// `false` at one the configuration excludes or cannot decide. Indexed from
/// 1; index 0 is unused. A file's own `#define`s count from where they are.
pub fn compiled_lines(source: &str, state: &ConfigState) -> Vec<bool> {
    scan(source, state, false).compiled
}

/// Whether `compiled` excludes any line holding code (not a directive, a
/// comment or blank) that names one of `names`, or a name the file itself
/// spells on a line together with one of them (`int nodes[MAX_NODES];`
/// makes `nodes` depend on the generated `MAX_NODES`): a line where the two
/// contexts could resolve a name differently. One hop, within the file; a
/// name a project header derives from a generated one is not followed.
pub fn excludes_code_naming(
    source: &str,
    compiled: &[bool],
    names: &std::collections::HashSet<String>,
) -> bool {
    let mut in_comment = false;
    let lines: Vec<String> = source
        .lines()
        .map(|l| strip_comments(l, &mut in_comment))
        .collect();
    // Code only: a configuration test such as `#ifdef HAVE_X` names the
    // generated macro but makes nothing else depend on it.
    let mut directive = false;
    let code: Vec<bool> = (0..lines.len())
        .map(|i| {
            !continues_directive(&lines, i, &mut directive)
                && !lines[i].trim_start().starts_with('#')
                && !lines[i].trim().is_empty()
        })
        .collect();
    let mut dependent: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for line in lines.iter().zip(&code).filter(|(_, c)| **c).map(|(l, _)| l) {
        if identifiers(line).any(|id| names.contains(id)) {
            dependent.extend(identifiers(line).filter(|id| !is_keyword(id)));
        }
    }
    for (i, line) in lines.iter().enumerate() {
        if !code[i] || compiled.get(i + 1).copied().unwrap_or(true) {
            continue;
        }
        if identifiers(line).any(|id| names.contains(id) || dependent.contains(id)) {
            return true;
        }
    }
    false
}

fn is_keyword(id: &str) -> bool {
    matches!(
        id,
        "auto"
            | "break"
            | "case"
            | "char"
            | "const"
            | "continue"
            | "default"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "extern"
            | "float"
            | "for"
            | "goto"
            | "if"
            | "inline"
            | "int"
            | "long"
            | "register"
            | "restrict"
            | "return"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "struct"
            | "switch"
            | "typedef"
            | "union"
            | "unsigned"
            | "void"
            | "volatile"
            | "while"
            | "_Alignas"
            | "_Alignof"
            | "_Atomic"
            | "_Bool"
            | "_Complex"
            | "_Generic"
            | "_Noreturn"
            | "_Static_assert"
            | "_Thread_local"
            | "alignas"
            | "alignof"
            | "bool"
            | "constexpr"
            | "false"
            | "nullptr"
            | "static_assert"
            | "thread_local"
            | "true"
            | "typeof"
            | "typeof_unqual"
            | "define"
            | "include"
    )
}

/// Every name a header defines at file scope: `#define`d macros, the names
/// a top-level declaration or definition declares (functions, typedefs,
/// objects, function pointers, struct, union and enum tags), and enumeration
/// constants. A function's body, a parameter list and a struct's members
/// declare nothing at file scope. Over-collecting only costs a second
/// analysis of a file; under-collecting would leave generated facts in an
/// excluded arm.
pub fn names_defined_in(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_comment = false;
    let lines: Vec<String> = text
        .lines()
        .map(|l| strip_comments(l, &mut in_comment))
        .collect();
    let mut scope = FileScope::default();
    // Each conditional's scope where it opened and where its first arm left
    // it: the arms of `#if A / int f(int a) { / #else / int f(long a) { /
    // #endif` each open the body once, not twice.
    let mut arms: Vec<(FileScope, Option<FileScope>)> = Vec::new();
    let mut directive = false;
    for i in 0..lines.len() {
        if continues_directive(&lines, i, &mut directive) {
            continue;
        }
        let Some(rest) = lines[i].trim_start().strip_prefix('#') else {
            scope.feed(&lines[i], &mut out);
            continue;
        };
        let (word, rest) = split_word(rest.trim_start());
        match word {
            "define" => out.extend(identifiers(rest).next().map(str::to_string)),
            "if" | "ifdef" | "ifndef" => arms.push((scope.clone(), None)),
            "elif" | "elifdef" | "elifndef" | "else" => {
                if let Some((at_open, first)) = arms.last_mut() {
                    if first.is_none() {
                        *first = Some(scope.clone());
                    }
                    scope = at_open.clone();
                }
            }
            "endif" => {
                if let Some((_, Some(first))) = arms.pop() {
                    scope = first;
                }
            }
            _ => {}
        }
    }
    out.retain(|n| !is_keyword(n));
    out.sort();
    out.dedup();
    out
}

/// Attribute-like names whose parenthesised operand is no declarator.
fn is_attribute_like(id: &str) -> bool {
    matches!(
        id,
        "__attribute__"
            | "__attribute"
            | "__declspec"
            | "__asm__"
            | "__asm"
            | "asm"
            | "_Alignas"
            | "alignas"
            | "_Static_assert"
            | "static_assert"
            | "__typeof__"
            | "typeof"
            | "_Pragma"
            | "__pragma"
    )
}

/// Reads a header's code at file scope, a statement at a time: what is
/// nested in parentheses, brackets and braces is blanked from the statement,
/// so only the file-scope names it declares are left to read.
#[derive(Debug, Clone, Default)]
struct FileScope {
    /// Brace depth.
    brace: usize,
    /// Parenthesis depth at file scope.
    paren: usize,
    /// Bracket depth at file scope.
    bracket: usize,
    /// The statement so far, at file scope.
    stmt: String,
    /// The text of the open outermost parenthesised group.
    group: String,
    /// The open group is an attribute, `asm` or static assertion.
    skip_group: bool,
    /// The open brace is a function's body.
    fn_body: bool,
    /// The open brace is an enumeration's body.
    enum_body: bool,
    /// Parenthesis depth inside an enumeration's body.
    enum_paren: usize,
    /// The next identifier in an enumeration's body names a constant.
    item_start: bool,
}

impl FileScope {
    fn feed(&mut self, code: &str, out: &mut Vec<String>) {
        let chars: Vec<char> = code.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            i += 1;
            if self.brace > 0 {
                match c {
                    '{' => self.brace += 1,
                    '}' => {
                        self.brace -= 1;
                        if self.brace == 0 {
                            self.close_body();
                        }
                    }
                    _ if self.enum_body && self.brace == 1 => match c {
                        '(' => self.enum_paren += 1,
                        ')' => self.enum_paren = self.enum_paren.saturating_sub(1),
                        ',' if self.enum_paren == 0 => self.item_start = true,
                        _ if c.is_ascii_alphanumeric() || c == '_' => {
                            let start = i - 1;
                            while i < chars.len()
                                && (chars[i].is_ascii_alphanumeric() || chars[i] == '_')
                            {
                                i += 1;
                            }
                            if self.item_start && !c.is_ascii_digit() {
                                out.push(chars[start..i].iter().collect());
                                self.item_start = false;
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
                continue;
            }
            if self.paren > 0 {
                match c {
                    '(' => self.paren += 1,
                    ')' => self.paren -= 1,
                    _ => {}
                }
                if self.paren == 0 {
                    self.close_group();
                } else {
                    self.group.push(c);
                }
                continue;
            }
            if self.bracket > 0 {
                match c {
                    '[' => self.bracket += 1,
                    ']' => self.bracket -= 1,
                    _ => {}
                }
                continue;
            }
            match c {
                '(' => self.open_group(),
                '[' => {
                    self.bracket = 1;
                    self.stmt.push(' ');
                }
                '{' => self.open_body(out),
                // A brace closing nothing: the end of `extern "C" {`.
                '}' => {}
                ';' => {
                    declared_names(&self.stmt, out);
                    self.stmt.clear();
                }
                _ => self.stmt.push(c),
            }
        }
        self.stmt.push(' ');
    }

    fn open_group(&mut self) {
        let trimmed = self.stmt.trim_end();
        let last = trimmed
            .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .next()
            .unwrap_or("");
        self.skip_group = is_attribute_like(last);
        if self.skip_group {
            let keep = trimmed.len() - last.len();
            self.stmt.truncate(keep);
        }
        self.paren = 1;
        self.group.clear();
    }

    /// `(*name)` or `(*name[N])` declares `name`, a pointer to a function
    /// (or an array of them); any other group declares nothing.
    fn close_group(&mut self) {
        if self.skip_group {
            self.stmt.push(' ');
            return;
        }
        let g = self.group.trim_start();
        let pointer = g
            .strip_prefix('*')
            .map(|r| r.trim_start_matches(|c: char| c == '*' || c.is_whitespace()))
            .and_then(|r| {
                identifiers(r).find(|id| !matches!(*id, "const" | "volatile" | "restrict"))
            });
        match pointer {
            Some(name) => {
                self.stmt.push_str("(*");
                self.stmt.push_str(name);
                self.stmt.push(')');
            }
            None => self.stmt.push_str("()"),
        }
    }

    fn open_body(&mut self, out: &mut Vec<String>) {
        let ids: Vec<&str> = identifiers(&self.stmt).collect();
        // `extern "C" {` opens no scope.
        if ids == ["extern"] && self.stmt.contains('"') {
            self.stmt.clear();
            return;
        }
        self.brace = 1;
        // The tag a body defines: `struct cfg { ... } cfg_default;`.
        if let Some(at) = ids
            .iter()
            .position(|id| matches!(*id, "struct" | "union" | "enum"))
        {
            out.extend(ids.get(at + 1).map(|t| t.to_string()));
        }
        if self.stmt.contains('=') {
            // An initializer: the statement goes on after it.
        } else if self.stmt.contains('(') {
            declared_names(&self.stmt, out);
            self.fn_body = true;
        } else if ids.contains(&"enum") {
            self.enum_body = true;
            self.item_start = true;
            self.enum_paren = 0;
        }
        self.stmt.push(' ');
    }

    fn close_body(&mut self) {
        if self.fn_body {
            self.stmt.clear();
        }
        self.fn_body = false;
        self.enum_body = false;
    }
}

/// The names a file-scope statement declares, its nested groups already
/// blanked: each declarator's `(*name)`, else the name before its parameter
/// list, else its last name before any initializer.
fn declared_names(stmt: &str, out: &mut Vec<String>) {
    for piece in stmt.split(',') {
        let piece = piece.split('=').next().unwrap_or("");
        let name = if let Some(at) = piece.find("(*") {
            identifiers(&piece[at..]).next()
        } else if let Some(at) = piece.find('(') {
            identifiers(&piece[..at]).last()
        } else {
            identifiers(piece).last()
        };
        out.extend(name.filter(|n| !is_keyword(n)).map(str::to_string));
    }
}

struct Scan {
    compiled: Vec<bool>,
    /// Every name the source defines or undefines, as it leaves it.
    bindings: HashMap<String, Binding>,
    /// Every name the source defines or undefines in any arm -> the names
    /// the conditions of its arms test.
    depends: HashMap<String, std::collections::HashSet<String>>,
}

/// One frame of the conditional stack.
struct Frame {
    /// The arm currently open is taken (`Some(true)`), not (`Some(false)`),
    /// or unknown.
    current: Option<bool>,
    /// Some earlier arm of this conditional was taken, as far as known.
    any_taken: Option<bool>,
    /// The names this conditional's conditions so far test (an `#else` arm
    /// depends on every condition before it).
    tests: Vec<String>,
}

fn scan(source: &str, state: &dyn Macros, guards_open: bool) -> Scan {
    let lines: Vec<&str> = source.lines().collect();
    let mut compiled = vec![true; lines.len() + 1];
    let mut local = View {
        base: state,
        local: HashMap::new(),
    };
    let mut stack: Vec<Frame> = Vec::new();
    let guard = if guards_open {
        include_guard(&lines)
    } else {
        None
    };
    let mut depends: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    let mut in_comment = false;
    let mut i = 0;
    while i < lines.len() {
        // A directive may continue over `\`-ended lines.
        let start = i;
        let mut logical = strip_comments(lines[i], &mut in_comment);
        while logical.trim_end().ends_with('\\') && i + 1 < lines.len() {
            logical = logical.trim_end().trim_end_matches('\\').to_string();
            i += 1;
            logical.push(' ');
            logical.push_str(&strip_comments(lines[i], &mut in_comment));
        }
        let effective = effective(&stack);
        for n in start..=i {
            compiled[n + 1] = effective == Some(true);
        }
        i += 1;
        let t = logical.trim();
        let Some(directive) = t.strip_prefix('#') else {
            continue;
        };
        let directive = directive.trim_start();
        let (word, rest) = split_word(directive);
        let tests = || identifiers(rest).map(str::to_string).collect::<Vec<_>>();
        if matches!(word, "define" | "undef") {
            if let Some(name) = identifiers(rest).next() {
                depends
                    .entry(name.to_string())
                    .or_default()
                    .extend(stack.iter().flat_map(|f| f.tests.iter().cloned()));
            }
        }
        match word {
            "ifdef" | "ifndef" => {
                let name = identifiers(rest).next().unwrap_or("");
                let is_guard =
                    word == "ifndef" && guard.as_deref() == Some(name) && stack.is_empty();
                let defined = match local.value_of(name) {
                    Lookup::Defined(_) => Some(true),
                    Lookup::Undefined => Some(false),
                    Lookup::Unknown => None,
                };
                let cond = if is_guard {
                    Some(true)
                } else if word == "ifdef" {
                    defined
                } else {
                    defined.map(|d| !d)
                };
                stack.push(Frame {
                    current: cond,
                    any_taken: cond,
                    tests: if is_guard { Vec::new() } else { tests() },
                });
            }
            "if" => {
                let cond = eval(rest, &local).map(|v| v != 0);
                stack.push(Frame {
                    current: cond,
                    any_taken: cond,
                    tests: tests(),
                });
            }
            "elif" | "elifdef" | "elifndef" => {
                if let Some(top) = stack.last_mut() {
                    let cond = match word {
                        "elif" => eval(rest, &local).map(|v| v != 0),
                        _ => {
                            let name = identifiers(rest).next().unwrap_or("");
                            let d = match local.value_of(name) {
                                Lookup::Defined(_) => Some(true),
                                Lookup::Undefined => Some(false),
                                Lookup::Unknown => None,
                            };
                            if word == "elifdef" {
                                d
                            } else {
                                d.map(|d| !d)
                            }
                        }
                    };
                    top.current = and(not(top.any_taken), cond);
                    top.any_taken = or(top.any_taken, cond);
                    top.tests.extend(tests());
                }
            }
            "else" => {
                if let Some(top) = stack.last_mut() {
                    top.current = not(top.any_taken);
                    top.any_taken = Some(true);
                }
            }
            "endif" => {
                stack.pop();
            }
            // Under an arm the state cannot decide, a definition may or may
            // not happen: the name is unknown from there on.
            "define" if effective != Some(false) => {
                let (name, body) = split_define(rest);
                if !name.is_empty() {
                    let binding = if effective.is_none() {
                        Binding::Unknown
                    } else if body.starts_with('(')
                        && rest.trim_start().starts_with(&format!("{name}("))
                    {
                        Binding::Defined(None)
                    } else {
                        Binding::Defined(int_value(&body))
                    };
                    local.local.insert(name, binding);
                }
            }
            "undef" if effective != Some(false) => {
                if let Some(name) = identifiers(rest).next() {
                    let binding = if effective.is_none() {
                        Binding::Unknown
                    } else {
                        Binding::Undefined
                    };
                    local.local.insert(name.to_string(), binding);
                }
            }
            _ => {}
        }
    }
    Scan {
        compiled,
        bindings: local.local,
        depends,
    }
}

/// Whether the arms on the stack are all taken: `Some(true)`, one is not:
/// `Some(false)`, or that cannot be decided.
fn effective(stack: &[Frame]) -> Option<bool> {
    let mut out = Some(true);
    for f in stack {
        out = and(out, f.current);
    }
    out
}

fn and(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    match (a, b) {
        (Some(false), _) | (_, Some(false)) => Some(false),
        (Some(true), Some(true)) => Some(true),
        _ => None,
    }
}

fn or(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    match (a, b) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), Some(false)) => Some(false),
        _ => None,
    }
}

fn not(a: Option<bool>) -> Option<bool> {
    a.map(|b| !b)
}

/// The macro a header's include guard tests: the header's first line of
/// code is `#ifndef G`, its next directive is `#define G`, and the `#endif`
/// closing that `#ifndef` is its last line of code. A header that only opens
/// with `#ifndef X` / `#define X` (a default, followed by more code) has no
/// guard.
fn include_guard(lines: &[&str]) -> Option<String> {
    let mut in_comment = false;
    let code: Vec<String> = lines
        .iter()
        .map(|l| strip_comments(l, &mut in_comment).trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    let directive = |l: &str| l.strip_prefix('#').map(|d| d.trim_start().to_string());
    let first = directive(code.first()?)?;
    let (w1, r1) = split_word(&first);
    if w1 != "ifndef" {
        return None;
    }
    let name = identifiers(r1).next()?.to_string();
    let second = directive(code.get(1)?)?;
    let (w2, r2) = split_word(&second);
    if w2 != "define" || identifiers(r2).next() != Some(name.as_str()) {
        return None;
    }
    // The #endif matching the first #ifndef ends the code.
    let mut depth = 0usize;
    let mut continued = false;
    for (i, line) in code.iter().enumerate() {
        let was_continued = continued;
        continued = line.ends_with('\\');
        if was_continued {
            continue;
        }
        let Some(d) = directive(line) else {
            continue;
        };
        match split_word(&d).0 {
            "if" | "ifdef" | "ifndef" => depth += 1,
            "endif" => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return (i + 1 == code.len()).then_some(name);
                }
            }
            _ => {}
        }
    }
    None
}

/// Implementation-reserved: `__x` or `_X` (C11 7.1.3).
fn is_reserved(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next() == Some('_')
        && chars
            .next()
            .is_some_and(|c| c == '_' || c.is_ascii_uppercase())
}

fn split_word(s: &str) -> (&str, &str) {
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(s.len());
    (&s[..end], &s[end..])
}

fn split_define(rest: &str) -> (String, String) {
    let rest = rest.trim_start();
    let (name, body) = split_word(rest);
    (name.to_string(), body.trim().to_string())
}

/// The value of a macro body that is an integer literal (or a parenthesised
/// one), else `None`.
fn int_value(body: &str) -> Option<i64> {
    let mut b = body.trim();
    while let Some(inner) = b.strip_prefix('(').and_then(|r| r.strip_suffix(')')) {
        b = inner.trim();
    }
    if b.is_empty() {
        return None;
    }
    parse_int(b)
}

fn parse_int(tok: &str) -> Option<i64> {
    let t = tok.trim_end_matches(['u', 'U', 'l', 'L']);
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()
    } else if t.len() > 1 && t.starts_with('0') && t.bytes().all(|b| b.is_ascii_digit()) {
        i64::from_str_radix(&t[1..], 8).ok()
    } else {
        t.parse().ok()
    }
}

/// `line` with `/* */` and `//` comments removed, carrying an open block
/// comment over to the next line, and the text of its string and character
/// literals blanked: `"/*"` and `"http://"` open no comment, and a name
/// spelled in a string is no use of it.
fn strip_comments(line: &str, in_comment: &mut bool) -> String {
    let mut out = String::new();
    let mut chars = line.chars().peekable();
    let mut prev = ' ';
    while let Some(c) = chars.next() {
        if *in_comment {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                *in_comment = false;
            }
            continue;
        }
        match (c, chars.peek()) {
            ('/', Some('*')) => {
                chars.next();
                *in_comment = true;
                out.push(' ');
            }
            ('/', Some('/')) => break,
            // A quote after a digit is a digit separator (`1'000'000`).
            ('"', _) | ('\'', _) if !(c == '\'' && prev.is_ascii_digit()) => {
                out.push(c);
                // To the closing quote, or the end of the line for an
                // unterminated one; an escape skips the character after it.
                while let Some(d) = chars.next() {
                    if d == c {
                        out.push(c);
                        break;
                    }
                    out.push(' ');
                    if d == '\\' && chars.next().is_some() {
                        out.push(' ');
                    }
                }
            }
            _ => out.push(c),
        }
        prev = c;
    }
    out
}

/// Whether `lines[i]` continues a directive: the line before it is part of
/// one and ends with `\`.
fn continues_directive(lines: &[String], i: usize, directive: &mut bool) -> bool {
    let line = &lines[i];
    let continues = *directive;
    let starts = !continues && line.trim_start().starts_with('#');
    *directive = (continues || starts) && line.trim_end().ends_with('\\');
    continues
}

fn identifiers(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| w.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'))
}

// ── #if expression evaluation, three-valued ────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(i64),
    Ident(String),
    Op(&'static str),
}

fn tokenize(s: &str) -> Option<Vec<Tok>> {
    const OPS: [&str; 22] = [
        "&&", "||", "==", "!=", "<=", ">=", "<<", ">>", "(", ")", "!", "~", "*", "/", "%", "+",
        "-", "<", ">", "&", "|", "^",
    ];
    let mut out = Vec::new();
    let mut rest = s.trim();
    while !rest.is_empty() {
        let c = rest.chars().next().unwrap();
        if c.is_whitespace() {
            rest = rest.trim_start();
            continue;
        }
        if c.is_ascii_digit() {
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric()))
                .unwrap_or(rest.len());
            out.push(Tok::Num(parse_int(&rest[..end])?));
            rest = &rest[end..];
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            let (w, r) = split_word(rest);
            out.push(Tok::Ident(w.to_string()));
            rest = r;
            continue;
        }
        let op = OPS.iter().find(|op| rest.starts_with(**op))?;
        out.push(Tok::Op(op));
        rest = &rest[op.len()..];
    }
    Some(out)
}

/// The value of a `#if` condition under `state`, or `None` when it cannot be
/// decided.
fn eval(expr: &str, state: &View) -> Val {
    let toks = tokenize(expr)?;
    let mut p = Parser {
        toks: &toks,
        pos: 0,
        state,
    };
    let v = p.expr(0)?;
    (p.pos == toks.len()).then_some(())?;
    v
}

struct Parser<'a> {
    toks: &'a [Tok],
    pos: usize,
    state: &'a View<'a>,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn bump(&mut self) -> Option<&Tok> {
        let t = self.toks.get(self.pos);
        self.pos += 1;
        t
    }

    fn eat(&mut self, op: &str) -> bool {
        if self.peek() == Some(&Tok::Op(op_static(op))) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Precedence climbing. The outer `Option` fails the parse; the inner
    /// one is the three-valued result.
    fn expr(&mut self, min_prec: u8) -> Option<Val> {
        let mut lhs = self.unary()?;
        while let Some(Tok::Op(op)) = self.peek() {
            let op = *op;
            let Some(prec) = binary_prec(op) else {
                break;
            };
            if prec < min_prec {
                break;
            }
            self.pos += 1;
            let rhs = self.expr(prec + 1)?;
            lhs = apply(op, lhs, rhs);
        }
        Some(lhs)
    }

    fn unary(&mut self) -> Option<Val> {
        if self.eat("!") {
            return Some(self.unary()?.map(|v| (v == 0) as i64));
        }
        if self.eat("-") {
            return Some(self.unary()?.map(|v| v.wrapping_neg()));
        }
        if self.eat("+") {
            return self.unary();
        }
        if self.eat("~") {
            return Some(self.unary()?.map(|v| !v));
        }
        if self.eat("(") {
            let v = self.expr(0)?;
            self.eat(")").then_some(())?;
            return Some(v);
        }
        match self.bump()?.clone() {
            Tok::Num(n) => Some(Some(n)),
            Tok::Ident(name) if name == "defined" => {
                let paren = self.eat("(");
                let Some(Tok::Ident(target)) = self.bump().cloned() else {
                    return None;
                };
                if paren {
                    self.eat(")").then_some(())?;
                }
                Some(match self.state.value_of(&target) {
                    Lookup::Defined(_) => Some(1),
                    Lookup::Undefined => Some(0),
                    Lookup::Unknown => None,
                })
            }
            Tok::Ident(name) => {
                // A function-like macro call: its expansion is not known here.
                if self.peek() == Some(&Tok::Op("(")) {
                    let mut depth = 0;
                    while let Some(t) = self.bump() {
                        match t {
                            Tok::Op("(") => depth += 1,
                            Tok::Op(")") => {
                                depth -= 1;
                                if depth == 0 {
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    return Some(None);
                }
                Some(match self.state.value_of(&name) {
                    Lookup::Defined(v) => v,
                    Lookup::Undefined => Some(0),
                    Lookup::Unknown => None,
                })
            }
            Tok::Op(_) => None,
        }
    }
}

fn op_static(op: &str) -> &'static str {
    match op {
        "!" => "!",
        "-" => "-",
        "+" => "+",
        "~" => "~",
        "(" => "(",
        ")" => ")",
        _ => "",
    }
}

fn binary_prec(op: &str) -> Option<u8> {
    Some(match op {
        "||" => 1,
        "&&" => 2,
        "|" => 3,
        "^" => 4,
        "&" => 5,
        "==" | "!=" => 6,
        "<" | ">" | "<=" | ">=" => 7,
        "<<" | ">>" => 8,
        "+" | "-" => 9,
        "*" | "/" | "%" => 10,
        _ => return None,
    })
}

fn apply(op: &str, a: Val, b: Val) -> Val {
    match op {
        "&&" => match (a, b) {
            (Some(0), _) | (_, Some(0)) => Some(0),
            (Some(_), Some(_)) => Some(1),
            _ => None,
        },
        "||" => match (a, b) {
            (Some(x), _) if x != 0 => Some(1),
            (_, Some(y)) if y != 0 => Some(1),
            (Some(_), Some(_)) => Some(0),
            _ => None,
        },
        _ => {
            let (a, b) = (a?, b?);
            Some(match op {
                "|" => a | b,
                "^" => a ^ b,
                "&" => a & b,
                "==" => (a == b) as i64,
                "!=" => (a != b) as i64,
                "<" => (a < b) as i64,
                ">" => (a > b) as i64,
                "<=" => (a <= b) as i64,
                ">=" => (a >= b) as i64,
                "<<" => a.checked_shl(b.try_into().ok()?)?,
                ">>" => a.checked_shr(b.try_into().ok()?)?,
                "+" => a.wrapping_add(b),
                "-" => a.wrapping_sub(b),
                "*" => a.wrapping_mul(b),
                "/" => a.checked_div(b)?,
                "%" => a.checked_rem(b)?,
                _ => return None,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(defs: &[(&str, Option<i64>)]) -> ConfigState {
        ConfigState {
            names: defs
                .iter()
                .map(|(n, v)| (n.to_string(), Binding::Defined(*v)))
                .collect(),
        }
    }

    /// The state `generated` and project `headers` (name, text) give.
    fn from_generated(generated: &[(&str, &str)], headers: &[(&str, &str)]) -> ConfigState {
        let dir = tempfile::tempdir().unwrap();
        let write = |set: &[(&str, &str)], sub: &str| -> Vec<std::path::PathBuf> {
            std::fs::create_dir_all(dir.path().join(sub)).unwrap();
            set.iter()
                .map(|(name, text)| {
                    let p = dir.path().join(sub).join(name);
                    std::fs::write(&p, text).unwrap();
                    p
                })
                .collect()
        };
        let g = write(generated, "gen");
        let h = write(headers, "src");
        ConfigState::build(
            None,
            g.iter().map(|p| p.as_path()),
            h.iter().map(|p| p.as_path()),
        )
    }

    /// The state `headers` (name, text) give, read in the order given.
    fn from_headers(headers: &[(&str, &str)]) -> ConfigState {
        let dir = tempfile::tempdir().unwrap();
        let paths: Vec<std::path::PathBuf> = headers
            .iter()
            .map(|(name, text)| {
                let p = dir.path().join(name);
                std::fs::write(&p, text).unwrap();
                p
            })
            .collect();
        ConfigState::build(None, [], paths.iter().map(|p| p.as_path()))
    }

    #[test]
    fn an_ifdef_the_configuration_leaves_off_is_excluded() {
        let src = "int a;\n#ifdef CONFIG_VTX\nint b;\n#else\nint c;\n#endif\nint d;\n";
        let c = compiled_lines(src, &state(&[]));
        assert!(c[1] && !c[3] && c[5] && c[7]);
        let c = compiled_lines(src, &state(&[("CONFIG_VTX", Some(1))]));
        assert!(c[3] && !c[5]);
    }

    #[test]
    fn values_compare_and_elif_is_evaluated() {
        let src =
            "#if MAX_NODES > 1\nint smp;\n#elif defined(UP)\nint up;\n#else\nint none;\n#endif\n";
        let c = compiled_lines(src, &state(&[("MAX_NODES", Some(1)), ("UP", None)]));
        assert!(!c[2] && c[4] && !c[6]);
    }

    #[test]
    fn a_reserved_name_or_a_macro_call_is_undecided() {
        let src = "#ifdef __GNUC__\nint g;\n#endif\n#if IS_ENABLED(X)\nint e;\n#endif\n#if defined(A) && 0\nint z;\n#endif\n";
        let c = compiled_lines(src, &state(&[]));
        assert!(!c[2] && !c[5] && !c[8]);
        let c = compiled_lines(src, &state(&[("__GNUC__", Some(12))]));
        assert!(c[2]);
    }

    #[test]
    fn a_project_header_derives_names_from_the_generated_ones() {
        let dir = tempfile::tempdir().unwrap();
        let gen = dir.path().join("gen_config.h");
        std::fs::write(
            &gen,
            "#define CONFIG_MAX_NUM_NODES 1\n/* disabled: CONFIG_ENABLE_SMP_SUPPORT */\n",
        )
        .unwrap();
        let config = dir.path().join("config.h");
        std::fs::write(
            &config,
            "#ifndef CONFIG_H\n#define CONFIG_H\n#include <gen_config.h>\n\
             #ifdef CONFIG_ENABLE_SMP_SUPPORT\n#define ENABLE_SMP_SUPPORT\n#endif\n\
             #ifndef CONFIG_ENABLE_SMP_SUPPORT\n#define UNIPROCESSOR 1\n#endif\n#endif\n",
        )
        .unwrap();
        let s = ConfigState::build(None, [gen.as_path()], [config.as_path()]);
        let c = compiled_lines(
            "#ifdef ENABLE_SMP_SUPPORT\nint smp;\n#endif\n#if UNIPROCESSOR\nint up;\n#endif\n",
            &s,
        );
        assert!(!c[2] && c[5]);
    }

    #[test]
    fn excluded_code_naming_a_generated_name_is_found() {
        let src = "#ifdef CONFIG_VTX\n    x = cap_ept_new(1); /* c */\n#endif\n// cap_ept_new\n";
        let c = compiled_lines(src, &state(&[]));
        let names = ["cap_ept_new".to_string()].into_iter().collect();
        assert!(excludes_code_naming(src, &c, &names));
        let other = ["other".to_string()].into_iter().collect();
        assert!(!excludes_code_naming(src, &c, &other));
        // One hop: an array sized by a generated value, used in an arm.
        let src = "int nodes[MAX];\n#if MAX > 1\n  nodes[i] = 0;\n#endif\n";
        let c = compiled_lines(src, &state(&[("MAX", Some(1))]));
        let names = ["MAX".to_string()].into_iter().collect();
        assert!(excludes_code_naming(src, &c, &names));
    }

    #[test]
    fn comments_with_non_ascii_text_are_stripped() {
        let mut open = false;
        assert_eq!(strip_comments("a /* “b” */ c // “d”", &mut open), "a   c ");
        assert_eq!(strip_comments("x /* “open", &mut open), "x  ");
        assert!(open);
        assert_eq!(strip_comments("still” */ y", &mut open), " y");
    }

    #[test]
    fn names_defined_in_a_header() {
        let names = names_defined_in(
            "#define N 1\nstatic inline int cap_get(const cap_t *c) { return 0; }\nint count(void);\ntypedef struct s s_t;\n",
        );
        for n in ["N", "cap_get", "count", "s_t"] {
            assert!(names.contains(&n.to_string()), "{n}: {names:?}");
        }
    }

    #[test]
    fn a_value_derived_from_a_header_that_sorts_first_is_settled_in_any_order() {
        // a_derive.h reads A_ON, which only b_config.h defines: read under
        // what the other headers define, it gives MODE 1, whichever header
        // is read first, and the first round's MODE 2 (read while A_ON
        // still looked undefined) does not outlive the round.
        let derive = (
            "a_derive.h",
            "#ifndef A_ON\n#define MODE 2\n#else\n#define MODE 1\n#endif\n",
        );
        let config = ("b_config.h", "#define A_ON 1\n");
        let member = "#if MODE == 1\nint one;\n#else\nint two;\n#endif\n";
        for order in [[derive, config], [config, derive]] {
            let c = compiled_lines(member, &from_headers(&order));
            assert!(c[2] && !c[4], "{order:?}");
            let c = compiled_lines("#ifdef MODE\nint m;\n#endif\n", &from_headers(&order));
            assert!(c[2], "{order:?}");
        }
    }

    #[test]
    fn a_name_a_header_defines_unless_defined_settles() {
        // The commonest header idiom: it must not read its own definition
        // as one made elsewhere and drop it.
        let defaults = (
            "defaults.h",
            "#ifndef DEFAULTS_H\n#define DEFAULTS_H\n#ifndef PAGE\n#define PAGE 4096\n#endif\n\
             #if !defined(FTS3) && defined(FTS4)\n#define FTS3 1\n#endif\n#endif\n",
        );
        let fts4 = ("fts4.h", "#define FTS4 1\n");
        let c = compiled_lines(
            "#if PAGE == 4096\nint p;\n#endif\n#ifdef FTS3\nint f;\n#endif\n",
            &from_headers(&[defaults, fts4]),
        );
        assert!(c[2] && c[5], "{c:?}");
        // Two headers that each define it unless defined: whichever is read
        // first defines it, so each sees the other's and the rounds never
        // settle. It is unknown.
        let other = (
            "other.h",
            "#ifndef OTHER_H\n#define OTHER_H\n#ifndef PAGE\n#define PAGE 512\n#endif\n#endif\n",
        );
        let s = from_headers(&[defaults, other]);
        let c = compiled_lines(
            "#ifdef PAGE\nint d;\n#endif\n#if PAGE == 4096\nint p;\n#endif\n",
            &s,
        );
        assert!(!c[2] && !c[5], "{c:?}");
    }

    #[test]
    fn a_default_from_absence_drops_once_the_generated_header_defines_the_name() {
        // The Kconfig pattern: a project header defaults a name from the
        // absence of a configuration option the generated header sets.
        let autoconf = ("autoconf.h", "#define CONFIG_SMP 1\n");
        let config = (
            "config.h",
            "#ifndef CONFIG_H\n#define CONFIG_H\n#ifndef CONFIG_SMP\n#define UP_ONLY 1\n#endif\n\
             #ifdef CONFIG_SMP\n#define NCPU 4\n#else\n#define NCPU 1\n#endif\n#endif\n",
        );
        let member = "#ifdef UP_ONLY\nint up;\n#endif\n#if NCPU == 4\nint four;\n#endif\n";
        for s in [
            from_generated(&[autoconf], &[config]),
            from_headers(&[autoconf, config]),
            from_headers(&[config, autoconf]),
        ] {
            let c = compiled_lines(member, &s);
            assert!(!c[2] && c[5], "{c:?}");
        }
    }

    #[test]
    fn a_chain_longer_than_the_rounds_leaves_its_tail_unknown() {
        // h{k}.h defines N{k+1} when N{k} is defined: one link per round,
        // more links than rounds. Where the rounds stop, every name still
        // to come is unknown, not undefined.
        let n = MAX_ROUNDS + 4;
        let texts: Vec<(String, String)> = (0..n)
            .map(|k| {
                let text = if k == 0 {
                    "#define N0 1\n".to_string()
                } else {
                    format!("#ifdef N{}\n#define N{k} 1\n#endif\n", k - 1)
                };
                (format!("h{k:02}.h"), text)
            })
            .collect();
        let headers: Vec<(&str, &str)> = texts
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        let s = from_headers(&headers);
        let last = n - 1;
        let c = compiled_lines(
            &format!("#ifndef N{last}\nint no;\n#endif\n#ifdef N{last}\nint yes;\n#endif\n#ifdef N1\nint one;\n#endif\n"),
            &s,
        );
        assert!(!c[2] && !c[5] && c[8], "{c:?}");
    }

    #[test]
    fn a_comment_opener_in_a_string_or_char_literal_opens_no_comment() {
        let header = ("cfg.h", "#define MAX 1\n");
        let src = "const char *pat = \"/*\";\n#if MAX > 4\nint big;\n#else\nint small;\n#endif\n\
                   const char *url = \"http://x\"; int after;\nchar q = '\"'; int z = 1'000;\n\
                   #if MAX > 4\nint big2;\n#endif\n";
        let c = compiled_lines(src, &from_headers(&[header]));
        assert!(!c[3] && c[5] && c[7] && !c[10], "{c:?}");
        let names = names_defined_in(src);
        for n in ["pat", "url", "after", "q", "z"] {
            assert!(names.contains(&n.to_string()), "{n}: {names:?}");
        }
    }

    #[test]
    fn a_name_defined_or_undefined_under_an_undecided_arm_is_unknown() {
        let proj = (
            "proj.h",
            "#ifdef __GNUC__\n#define HAVE_B 1\n#endif\n\
             #define HAVE_C 1\n#if defined(__clang__)\n#undef HAVE_C\n#endif\n",
        );
        let s = from_headers(&[proj]);
        let src = "#ifndef HAVE_B\nint fallback;\n#endif\n#ifdef HAVE_C\nint c;\n#endif\n\
                   #ifdef __GNUC__\n#define LOCAL 1\n#endif\n#ifdef LOCAL\nint a;\n#else\nint b;\n#endif\n";
        let c = compiled_lines(src, &s);
        assert!(!c[2] && !c[5] && !c[11] && !c[13], "{c:?}");
    }

    #[test]
    fn only_file_scope_names_are_defined_by_a_header() {
        let header = "static inline int helper(int v)\n{\n    int local = v;\n    if (v) return 0;\n\
                      \x20   while (local) local--;\n    return local;\n}\n\
                      typedef void (*cb_t)(int);\n\
                      enum mode { MODE_A, MODE_B = (1 << 2), MODE_C };\n\
                      struct cfg { int field; } cfg_default;\n\
                      int table[COUNT], other;\n\
                      int __attribute__((unused)) quiet;\n\
                      #define WRAP(x) \\\n    do { wrapped(x); } while (0)\n\
                      #ifdef __cplusplus\nextern \"C\" {\n#endif\n\
                      #ifdef ALT\nint pick(int a) {\n#else\nint pick(long a) {\n#endif\n    return 0;\n}\n\
                      int later(void);\n\
                      #ifdef __cplusplus\n}\n#endif\n";
        let names = names_defined_in(header);
        for n in [
            "helper",
            "cb_t",
            "mode",
            "MODE_A",
            "MODE_B",
            "MODE_C",
            "cfg",
            "cfg_default",
            "table",
            "other",
            "quiet",
            "WRAP",
            "pick",
            "later",
        ] {
            assert!(names.contains(&n.to_string()), "{n}: {names:?}");
        }
        for n in [
            "if", "return", "while", "do", "v", "local", "field", "a", "wrapped", "x", "COUNT",
            "int", "unused",
        ] {
            assert!(!names.contains(&n.to_string()), "{n}: {names:?}");
        }
        // A member whose only excluded line is a statement like the
        // header's body is not split.
        let names: std::collections::HashSet<String> = names.into_iter().collect();
        let member =
            "int f(int v)\n{\n#ifdef OFF\n    if (v) return 0;\n#endif\n    return 1;\n}\n";
        let c = compiled_lines(member, &from_headers(&[]));
        assert!(!c[4]);
        assert!(!excludes_code_naming(member, &c, &names));
    }

    #[test]
    fn a_default_that_opens_a_header_is_no_include_guard() {
        // `#ifndef USE_FAST / #define USE_FAST 1 / #endif` followed by more
        // code is a default, not a guard: USE_FAST is defined.
        let fast = (
            "fast.h",
            "#ifndef USE_FAST\n#define USE_FAST 1\n#endif\nint fast_path(void);\n",
        );
        let member = "#ifdef USE_FAST\nint f;\n#else\nint s;\n#endif\n";
        let c = compiled_lines(member, &from_headers(&[fast]));
        assert!(c[2] && !c[4], "{c:?}");
        // Two such headers, each defaulting Y to its own value, and `#ifndef
        // Y` is never compiled. With code after the default, each header
        // defines Y only while the other has not, so the rounds never settle
        // and Y is unknown. When the default closes the file it is each
        // header's include guard, taken as open and recorded: Y is defined,
        // with no known value.
        for (tail, binding) in [
            ("int more;\n", Binding::Unknown),
            ("", Binding::Defined(None)),
        ] {
            let y1 = ("y1.h", format!("#ifndef Y\n#define Y 1\n#endif\n{tail}"));
            let y2 = ("y2.h", format!("#ifndef Y\n#define Y 2\n#endif\n{tail}"));
            let s = from_headers(&[(y1.0, y1.1.as_str()), (y2.0, y2.1.as_str())]);
            assert_eq!(s.names.get("Y"), Some(&binding), "{tail:?}");
            let c = compiled_lines("#ifndef Y\nint none;\n#endif\n", &s);
            assert!(!c[2], "{tail:?}: {c:?}");
        }
    }

    #[test]
    fn a_real_include_guard_is_defined_for_every_other_file() {
        let guarded = (
            "g.h",
            "/* g */\n#ifndef G_H\n#define G_H\nint g(void);\n#endif /* G_H */\n",
        );
        let reader = ("r.h", "#ifdef G_H\n#define SAW_G 1\n#endif\nint r;\n");
        let s = from_headers(&[guarded, reader]);
        let c = compiled_lines(
            "#ifdef G_H\nint a;\n#endif\n#ifdef SAW_G\nint b;\n#endif\n#if !defined(G_H)\nint c;\n#endif\n",
            &s,
        );
        assert!(c[2] && c[5] && !c[8], "{c:?}");
        // The guard is still open for the header itself.
        let lines: Vec<&str> = guarded.1.lines().collect();
        assert_eq!(include_guard(&lines).as_deref(), Some("G_H"));
        let lines: Vec<&str> = "#ifndef X\n#define X 1\n#endif\nint x;\n".lines().collect();
        assert_eq!(include_guard(&lines), None);
    }

    #[test]
    fn a_header_undefining_a_generated_name_leaves_it_unknown() {
        let autoconf = ("autoconf.h", "#define CONFIG_X 1\n#define CONFIG_Y 1\n");
        let compat = ("compat.h", "#undef CONFIG_X\nint compat;\n");
        let c = compiled_lines(
            "#ifdef CONFIG_X\nint x;\n#endif\n#ifdef CONFIG_Y\nint y;\n#endif\n",
            &from_generated(&[autoconf], &[compat]),
        );
        assert!(!c[2] && c[5], "{c:?}");
    }
}
