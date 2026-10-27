//! Assert-style macros that cannot be compiled out: a macro whose every
//! definition evaluates one parameter and, when it is false, calls something
//! that never returns.
//!
//! ADR-0011 basis 3 accepts "an assert or abort macro with no build-flag arm"
//! as proof in the scanned source, and ADR-0010 Decision 5 is the other half:
//! an `NDEBUG`-strippable `assert()` guards nothing, because the release
//! configuration exists. valkey's
//!
//! ```c
//! #define serverAssert(_e) (likely(_e) ? (void)0 : (_serverAssert(#_e, __FILE__, __LINE__), valkey_unreachable()))
//! ```
//!
//! has no other definition anywhere in the tree, so `serverAssert(p != NULL);`
//! guards what follows it in every configuration.
//!
//! Recognition is by what the macro *expands to*, never by its name:
//!
//! * **Every definition counts.** All `#define`s of a name across the project
//!   are kept, in every preprocessor arm, and a name qualifies only when each
//!   one is a check on the same parameter. A `#ifdef NDEBUG` arm defining it as
//!   `((void)0)` (or any other build-flag arm that does not check) disqualifies
//!   the name, which is ADR-0010's "every compilable configuration counts".
//!   Only a region the file itself proves dead (`#if 0`, ADR-0011 basis 2) is
//!   skipped. A variadic or token-pasting definition cannot be analyzed, so it
//!   disqualifies the name too.
//! * **The check is unconditional.** The recognized shapes are
//!   `C ? (void)0 : FAIL`, `!C ? FAIL : (void)0`, `C || FAIL`, `!C && FAIL`,
//!   and `if (!C) FAIL` (optionally in `do { ... } while (0)`), where `C`
//!   reduces to the parameter through parentheses, `!!`, `__builtin_expect`
//!   and truthiness-preserving macros such as `likely`. A runtime-gated
//!   variant like valkey's `debugServerAssert` —
//!   `(server.enable_debug_assert ? serverAssert(x) : (void)0)` — checks
//!   nothing when the switch is off, so it matches none of them (ADR-0011
//!   basis 5). It is also variadic.
//! * **FAIL never returns.** It calls a function the project knows is
//!   noreturn (`abort`, `exit`, `_Noreturn`, `__attribute__((noreturn))`,
//!   ...), `__builtin_trap`, or a macro every definition of which does. A
//!   branch that consists only of `__builtin_unreachable()` is an *assume*
//!   (`MBEDTLS_ASSUME`, miniaudio's `MA_ASSUME`): no check runs, the compiler
//!   is told the condition holds, which is basis 4, not proof. It counts only
//!   after a call that reports the failure, as in `serverAssert`'s
//!   `(_serverAssert(...), valkey_unreachable())`.
//! * **`assert` itself never qualifies**, whatever the project defines it as:
//!   `<assert.h>` supplies the `NDEBUG` definition (C11 7.2), and a file that
//!   includes it rather than the project's replacement header gets that one.

use std::collections::{HashMap, HashSet};

/// One `#define` of a name, as written.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MacroDefinition {
    /// `#define NAME(params) body`. Stringized parameters (`#p`) are replaced
    /// by `""` in `body`: they only ever produce a message string.
    Function {
        /// Parameter names in order.
        params: Vec<String>,
        /// Normalized replacement list.
        body: String,
    },
    /// `#define NAME body`.
    Object {
        /// Normalized replacement list.
        body: String,
    },
    /// A definition this module cannot reason about: variadic, token paste
    /// (`##`), or a parameter list that never closes.
    Opaque,
}

/// Every `#define` in `source`, in every preprocessor arm except those the
/// file itself proves dead, keyed by name, each distinct definition once.
pub fn collect_macro_definitions(source: &str) -> HashMap<String, Vec<MacroDefinition>> {
    let dead: Vec<(usize, usize)> = lang_parsing_substrate::dead_code_ranges(source)
        .into_iter()
        .map(|r| (r.start_line, r.end_line))
        .collect();
    let lines: Vec<&str> = source.lines().collect();
    let mut out: HashMap<String, Vec<MacroDefinition>> = HashMap::new();
    let mut i = 0;
    while i < lines.len() {
        let first_line = i + 1;
        let mut logical = String::new();
        while i < lines.len() {
            let te = lines[i].trim_end();
            i += 1;
            if let Some(stripped) = te.strip_suffix('\\') {
                logical.push_str(stripped);
                logical.push(' ');
            } else {
                logical.push_str(te);
                break;
            }
        }
        if dead
            .iter()
            .any(|&(s, e)| first_line >= s && first_line <= e)
        {
            continue;
        }
        if let Some((name, def)) = parse_define(&logical) {
            let defs = out.entry(name).or_default();
            if !defs.contains(&def) {
                defs.push(def);
            }
        }
    }
    out
}

/// Fold one file's definitions into the project-wide table.
pub fn merge_macro_definitions(
    into: &mut HashMap<String, Vec<MacroDefinition>>,
    from: HashMap<String, Vec<MacroDefinition>>,
) {
    for (name, defs) in from {
        let slot = into.entry(name).or_default();
        for def in defs {
            if !slot.contains(&def) {
                slot.push(def);
            }
        }
    }
}

/// Names `#define`d inside a live `#if`/`#ifdef`/`#ifndef` arm of `source`,
/// at any depth. Such a name has a configuration in which that definition is
/// absent, and when no other arm supplies one the name is not a macro there
/// at all: sqlite's `sqliteInt.h` defines `memcpy(D,S,N)` as a `{ }` block
/// only under `#ifdef SQLITE_INLINE_MEMCPY`, and every other build calls the
/// library function (ADR-0010). A name every live arm of an `#if` ...
/// `#else` group defines is not conditional, and neither is one the file also
/// defines outside any conditional: every configuration has a definition, and
/// a consumer still has to agree with each of them. An include guard is not
/// a configuration and does not count; neither does a region the file itself
/// proves dead, whose definitions no build sees.
pub fn collect_conditional_macro_names(source: &str) -> HashSet<String> {
    let dead: Vec<(usize, usize)> = lang_parsing_substrate::dead_code_ranges(source)
        .into_iter()
        .map(|r| (r.start_line, r.end_line))
        .collect();
    let directives = logical_directives(source);
    let keyword = directive_keyword;

    let is_dead = |line: usize| dead.iter().any(|&(s, e)| line >= s && line <= e);
    // One entry per open conditional: whether it is a file-level include
    // guard, whether an `#else` has been seen, and for each arm so far the
    // names it defines in every configuration that reaches it (`None` for
    // an arm the file proves dead, which no build takes).
    struct Group {
        guard: bool,
        has_else: bool,
        arms: Vec<Option<HashSet<String>>>,
    }
    let arm_at = |line: usize, k: usize| -> Option<HashSet<String>> {
        // An arm with a body is dead when its first line is; an empty arm
        // stays live, which only ever withholds coverage.
        let has_body = directives.get(k + 1).is_none_or(|(next, d)| {
            *next > line + 1
                || !matches!(
                    keyword(d).as_str(),
                    "elif" | "elifdef" | "elifndef" | "else" | "endif"
                )
        });
        (!(has_body && is_dead(line + 1))).then(HashSet::new)
    };
    let mut open: Vec<Group> = Vec::new();
    let mut inside = HashSet::new();
    let mut everywhere: HashSet<String> = HashSet::new();
    for (k, (line, d)) in directives.iter().enumerate() {
        match keyword(d).as_str() {
            "if" | "ifdef" | "ifndef" => {
                let is_guard = open.is_empty() && opens_include_guard(&directives, k);
                open.push(Group {
                    guard: is_guard,
                    has_else: false,
                    arms: vec![arm_at(*line, k)],
                });
            }
            kw @ ("elif" | "elifdef" | "elifndef" | "else") => {
                if let Some(g) = open.last_mut() {
                    g.has_else |= kw == "else";
                    g.arms.push(arm_at(*line, k));
                }
            }
            "endif" => {
                let Some(g) = open.pop() else { continue };
                // A group with an `#else` defines a name in every
                // configuration when each live arm does.
                let covered: HashSet<String> = if g.guard || !g.has_else {
                    HashSet::new()
                } else {
                    let mut live = g.arms.into_iter().flatten();
                    live.next()
                        .map(|first| live.fold(first, |acc, arm| &acc & &arm))
                        .unwrap_or_default()
                };
                match open.iter_mut().rev().find(|o| !o.guard) {
                    Some(parent) => {
                        if let Some(Some(arm)) = parent.arms.last_mut() {
                            arm.extend(covered);
                        }
                    }
                    None => everywhere.extend(covered),
                }
            }
            "define" => {
                if is_dead(*line) {
                    continue;
                }
                let Some((name, _)) = parse_define(&format!("#{d}")) else {
                    continue;
                };
                match open.iter_mut().rev().find(|o| !o.guard) {
                    Some(g) => {
                        if let Some(Some(arm)) = g.arms.last_mut() {
                            arm.insert(name.clone());
                        }
                        inside.insert(name);
                    }
                    None => {
                        everywhere.insert(name);
                    }
                }
            }
            _ => {}
        }
    }
    inside.retain(|n| !everywhere.contains(n));
    inside
}

/// Each directive of `source` (a logical line, continuations joined, whose
/// first non-blank character is `#`): its first physical line, from 1, and
/// its text after the `#`.
fn logical_directives(source: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = source.lines().collect();
    let mut directives: Vec<(usize, String)> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let first_line = i + 1;
        let mut logical = String::new();
        while i < lines.len() {
            let te = lines[i].trim_end();
            i += 1;
            if let Some(stripped) = te.strip_suffix('\\') {
                logical.push_str(stripped);
                logical.push(' ');
            } else {
                logical.push_str(te);
                break;
            }
        }
        if let Some(d) = logical.trim_start().strip_prefix('#') {
            directives.push((first_line, d.trim_start().to_string()));
        }
    }
    directives
}

/// A directive's keyword: `ifdef` of `ifdef X`.
fn directive_keyword(d: &str) -> String {
    d.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// Whether the conditional `directives[k]` opens an include guard: an
/// `#ifndef X` / `#if !defined(X)` whose next directive is `#define X`.
/// Only a conditional at file level can be one; the caller checks that.
fn opens_include_guard(directives: &[(usize, String)], k: usize) -> bool {
    let d = directives[k].1.as_str();
    let rest = if let Some(r) = d.strip_prefix("ifndef") {
        r
    } else {
        let Some(r) = d
            .strip_prefix("if")
            .and_then(|r| r.trim_start().strip_prefix('!'))
            .and_then(|r| r.trim_start().strip_prefix("defined"))
        else {
            return false;
        };
        let r = r.trim_start();
        r.strip_prefix('(').unwrap_or(r)
    };
    let guard: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    !guard.is_empty()
        && directives.get(k + 1).is_some_and(|(_, next)| {
            next.strip_prefix("define")
                .map(str::trim_start)
                .and_then(|n| n.strip_prefix(guard.as_str()))
                .is_some_and(|r| !r.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_'))
        })
}

/// Whether the include guard `directives[k]` opens ([`opens_include_guard`])
/// is only a guard for [`ObjectMacroTimeline`]: the conditional encloses the
/// whole file, its `#ifndef` the first directive and its `#endif` the last,
/// with nothing but blank lines and comments (a licence block) outside them.
/// What its `#define` gives the name does not matter. A default-value block
/// anywhere else -- `#ifndef NULL` / `#define NULL (void *)0`, `#ifndef M` /
/// `#define M 1`, an empty feature flag -- supplies its definition only
/// where nothing defined the name before, so it stays a build alternative.
fn only_guards(source: &str, directives: &[(usize, String)], k: usize) -> bool {
    if k != 0 {
        return false;
    }
    let mut depth = 0usize;
    let Some(end_at) = directives.iter().position(|(_, d)| {
        match directive_keyword(d).as_str() {
            "if" | "ifdef" | "ifndef" => depth += 1,
            "endif" => depth = depth.saturating_sub(1),
            _ => {}
        }
        depth == 0
    }) else {
        return false;
    };
    if end_at + 1 != directives.len() {
        return false;
    }
    let (start, end) = (directives[0].0, directives[end_at].0);
    crate::utility::cert_c::pp_tokens::mask_source(source)
        .lines()
        .enumerate()
        .all(|(i, l)| (start..=end).contains(&(i + 1)) || l.trim().is_empty())
}

/// One `#define` or `#undef` of a name, as [`default_value_defines`] reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameDirective {
    /// A default value's `#define`: directly in the then-arm of a group whose
    /// whole condition is `#ifndef X` or `#if !defined(X)` for the name it
    /// defines, with no conditional around that group but the file's include
    /// guard.
    Default,
    /// Any other `#define`.
    Define,
    /// An `#undef`.
    Undef,
}

/// Every `#define` and `#undef` of each name in `source`, in file order: the
/// directive's first line and which kind it is. A default value
/// ([`NameDirective::Default`]) leaves the name defined in every build after
/// it, whether it ran or the name was defined before (a platform's own
/// `#define` included): a default's absence is not a build that lacks the
/// name. Only an `#undef` after it can change that. sqlite's `#if
/// !defined(NDEBUG) && !defined(SQLITE_DEBUG)` / `# define NDEBUG 1` has
/// another conjunct and is no default.
pub fn default_value_defines(source: &str) -> HashMap<String, Vec<(usize, NameDirective)>> {
    /// One open group: whether it is the include guard, the name its whole
    /// condition says is undefined, and whether its first arm is being read.
    struct Group {
        guard: bool,
        defaults: Option<String>,
        then_arm: bool,
    }
    let masked = crate::utility::cert_c::pp_tokens::mask_source(source);
    let directives = logical_directives(&masked);
    let mut open: Vec<Group> = Vec::new();
    let mut out: HashMap<String, Vec<(usize, NameDirective)>> = HashMap::new();
    for (k, (line, d)) in directives.iter().enumerate() {
        let keyword = directive_keyword(d);
        match keyword.as_str() {
            "if" | "ifdef" | "ifndef" => open.push(Group {
                guard: open.is_empty()
                    && opens_include_guard(&directives, k)
                    && only_guards(&masked, &directives, k),
                defaults: whole_ifndef(d),
                then_arm: true,
            }),
            "elif" | "elifdef" | "elifndef" | "else" => {
                if let Some(group) = open.last_mut() {
                    group.then_arm = false;
                }
            }
            "endif" => {
                open.pop();
            }
            "define" | "undef" => {
                let name: String = d[keyword.len()..]
                    .trim_start()
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if name.is_empty() {
                    continue;
                }
                let default = open.split_last().is_some_and(|(inner, outer)| {
                    inner.then_arm
                        && inner.defaults.as_deref() == Some(name.as_str())
                        && outer.iter().all(|g| g.guard)
                });
                let directive = match (keyword.as_str(), default) {
                    ("undef", _) => NameDirective::Undef,
                    (_, true) => NameDirective::Default,
                    (_, false) => NameDirective::Define,
                };
                out.entry(name).or_default().push((*line, directive));
            }
            _ => {}
        }
    }
    out
}

/// `X` when the conditional `d` is exactly `ifndef X`, `if !defined(X)` or
/// `if !defined X`, with nothing else in its condition.
fn whole_ifndef(d: &str) -> Option<String> {
    let rest = match directive_keyword(d).as_str() {
        "ifndef" => d["ifndef".len()..].trim(),
        "if" => {
            let r = d["if".len()..]
                .trim_start()
                .strip_prefix('!')?
                .trim_start()
                .strip_prefix("defined")?
                .trim();
            match r.strip_prefix('(') {
                Some(r) => r.strip_suffix(')')?.trim(),
                None => r,
            }
        }
        _ => return None,
    };
    let is_name = !rest.is_empty()
        && !rest.starts_with(|c: char| c.is_ascii_digit())
        && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    is_name.then(|| rest.to_string())
}

/// One file's `#define`s and `#undef`s of object-like macros, in order, for
/// asking what a name stands for at a given line.
///
/// A later directive replaces an earlier one only in the builds that reach
/// both: one at the same or an outer level of conditionals (`#define M
/// KEY_WRITE`, `#undef M`, `#define M KEY_READ` leaves only `KEY_READ`),
/// while the arms of an `#if` ... `#else` group, or an arm and the code
/// around it, are different builds whose definitions are alternatives
/// (ADR-0010 D1). A group with an `#else` whose every arm replaces the name
/// (or that the file proves dead) leaves only its arms' definitions: every
/// build that reaches its `#endif` took one of them. An include guard is not
/// a build alternative ([`only_guards`]), and a region the file proves dead
/// holds nothing.
///
/// Each name's alternatives are built once, in one pass, as a persistent
/// stack with one head per directive, so a lookup is a binary search for the
/// line and a walk of the alternatives in force there.
///
/// **Limitation:** where `#include` lines fall is not read. An included
/// header's definitions are taken as standing before the file's first
/// directive, so a header included after the file's own `#define` is read
/// as if the file's definition replaced it.
#[derive(Debug, Default)]
pub struct ObjectMacroTimeline {
    names: HashMap<String, NameTimeline>,
    /// Every directive's first physical line, in file order.
    directive_lines: Vec<usize>,
}

/// One directive of a name, as [`ObjectMacroTimeline::of`] reads it.
#[derive(Debug)]
enum MacroStep {
    /// A `#define` (`body` is its object-like replacement list, `None` when
    /// it is not object-like) or an `#undef` (`None`), in the conditional
    /// arms `arms`, outermost first, each a number unique within the file
    /// and increasing in file order.
    Set {
        body: Option<String>,
        arms: Vec<usize>,
    },
    /// The `#endif` of a group with an `#else` that every arm replaces the
    /// name in: the group sits in `arms`, and its arms are numbered from
    /// `first_arm` on.
    GroupReplaces { arms: Vec<usize>, first_arm: usize },
}

/// One alternative on a name's persistent stack.
#[derive(Debug)]
struct Alternative {
    /// The replacement list; `None` for the definition from before the file.
    body: Option<String>,
    /// The conditional arms it sits in.
    arms: Vec<usize>,
    /// The alternative below it.
    below: Option<usize>,
}

/// One name's alternatives after each of its directives.
#[derive(Debug, Default)]
struct NameTimeline {
    /// Every alternative ever pushed; index 0 is the definition from before
    /// the file.
    alternatives: Vec<Alternative>,
    /// Each directive's first physical line, in file order.
    lines: Vec<usize>,
    /// The top of the stack after each directive.
    heads: Vec<Option<usize>>,
}

impl NameTimeline {
    fn build(steps: Vec<(usize, MacroStep)>) -> Self {
        let mut timeline = NameTimeline {
            alternatives: vec![Alternative {
                body: None,
                arms: Vec::new(),
                below: None,
            }],
            lines: Vec::with_capacity(steps.len()),
            heads: Vec::with_capacity(steps.len()),
        };
        let mut head = Some(0);
        for (line, step) in steps {
            head = match step {
                // A directive replaces what the builds reaching it saw since
                // its innermost arm opened, which is the top of the stack:
                // each alternative is popped at most once along the file.
                MacroStep::Set { body, arms } => {
                    let mut top = head;
                    while let Some(i) =
                        top.filter(|&i| timeline.alternatives[i].arms.starts_with(&arms))
                    {
                        top = timeline.alternatives[i].below;
                    }
                    // An `#undef` in an arm leaves the name undefined in the
                    // builds that take it, and an undefined name stands for
                    // nothing.
                    match body {
                        Some(body) => timeline.push(body.into(), arms, top),
                        None => top,
                    }
                }
                // The group's own alternatives are on top; under them, those
                // from before the group within its enclosing arm, which every
                // arm replaced; under those, ones other builds still see.
                MacroStep::GroupReplaces { arms, first_arm } => {
                    let in_group = |a: &Alternative| {
                        a.arms.len() > arms.len() && a.arms[arms.len()] >= first_arm
                    };
                    let mut kept = Vec::new();
                    let mut top = head;
                    while let Some(i) = top.filter(|&i| in_group(&timeline.alternatives[i])) {
                        kept.push(i);
                        top = timeline.alternatives[i].below;
                    }
                    while let Some(i) =
                        top.filter(|&i| timeline.alternatives[i].arms.starts_with(&arms))
                    {
                        top = timeline.alternatives[i].below;
                    }
                    for i in kept.into_iter().rev() {
                        let (body, arms) = (
                            timeline.alternatives[i].body.clone(),
                            timeline.alternatives[i].arms.clone(),
                        );
                        top = timeline.push(body, arms, top);
                    }
                    top
                }
            };
            timeline.lines.push(line);
            timeline.heads.push(head);
        }
        timeline
    }

    fn push(
        &mut self,
        body: Option<String>,
        arms: Vec<usize>,
        below: Option<usize>,
    ) -> Option<usize> {
        self.alternatives.push(Alternative { body, arms, below });
        Some(self.alternatives.len() - 1)
    }
}

/// What [`ObjectMacroTimeline::in_force`] finds for one name.
#[derive(Debug, PartialEq, Eq)]
pub struct InForce {
    /// Every object-like replacement list the name may have, each once,
    /// sorted.
    pub bodies: Vec<String>,
    /// Whether some build reaches the line with none of this file's
    /// directives of the name applying, so a definition from before the file
    /// (an included header's) still stands there.
    pub inherits: bool,
}

/// One open conditional, as [`ObjectMacroTimeline::of`] reads the file.
struct OpenGroup {
    /// An include guard: its arms are not build alternatives.
    guard: bool,
    /// The number of the arm being read, and of the group's first.
    arm: usize,
    first_arm: usize,
    has_else: bool,
    /// The names a directive at the current arm's own level replaces, and
    /// whether the file proves the arm dead.
    replaced: HashSet<String>,
    dead: bool,
    /// The names every finished arm replaced; `None` while no live arm has
    /// finished.
    every_arm: Option<HashSet<String>>,
}

impl OpenGroup {
    fn finish_arm(&mut self) {
        let replaced = std::mem::take(&mut self.replaced);
        if self.dead {
            return;
        }
        self.every_arm = Some(match self.every_arm.take() {
            None => replaced,
            Some(every) => every.intersection(&replaced).cloned().collect(),
        });
    }
}

impl ObjectMacroTimeline {
    /// The timeline of `source`.
    pub fn of(source: &str) -> Self {
        let dead: Vec<(usize, usize)> = lang_parsing_substrate::dead_code_ranges(source)
            .into_iter()
            .map(|r| (r.start_line, r.end_line))
            .collect();
        let is_dead = |line: usize| dead.iter().any(|&(s, e)| line >= s && line <= e);
        // The arm a directive on `line` opens is dead when a dead region
        // starts right after it.
        let opens_dead = |line: usize| {
            dead.iter()
                .any(|&(s, e)| s == line + 1 || (line + 1 >= s && line < e))
        };
        let directives = logical_directives(source);
        let mut open: Vec<OpenGroup> = Vec::new();
        let mut next_arm = 0;
        let mut steps: HashMap<String, Vec<(usize, MacroStep)>> = HashMap::new();
        let arms_of = |open: &[OpenGroup]| -> Vec<usize> {
            open.iter().filter(|g| !g.guard).map(|g| g.arm).collect()
        };
        for (k, (line, d)) in directives.iter().enumerate() {
            let (name, body) = match directive_keyword(d).as_str() {
                "if" | "ifdef" | "ifndef" => {
                    let guard = open.is_empty()
                        && opens_include_guard(&directives, k)
                        && only_guards(source, &directives, k);
                    next_arm += 1;
                    open.push(OpenGroup {
                        guard,
                        arm: next_arm,
                        first_arm: next_arm,
                        has_else: false,
                        replaced: HashSet::new(),
                        dead: opens_dead(*line),
                        every_arm: None,
                    });
                    continue;
                }
                kw @ ("elif" | "elifdef" | "elifndef" | "else") => {
                    next_arm += 1;
                    if let Some(group) = open.last_mut() {
                        group.finish_arm();
                        group.arm = next_arm;
                        group.has_else |= kw == "else";
                        group.dead = opens_dead(*line);
                    }
                    continue;
                }
                "endif" => {
                    let Some(mut group) = open.pop() else {
                        continue;
                    };
                    group.finish_arm();
                    if group.guard || !group.has_else {
                        continue;
                    }
                    let arms = arms_of(&open);
                    for name in group.every_arm.into_iter().flatten() {
                        if let Some(outer) = open.last_mut().filter(|g| !g.guard) {
                            outer.replaced.insert(name.clone());
                        }
                        steps.entry(name).or_default().push((
                            *line,
                            MacroStep::GroupReplaces {
                                arms: arms.clone(),
                                first_arm: group.first_arm,
                            },
                        ));
                    }
                    continue;
                }
                "define" => match parse_define(&format!("#{d}")) {
                    Some((name, MacroDefinition::Object { body })) => (name, Some(body)),
                    Some((name, _)) => (name, None),
                    None => continue,
                },
                "undef" => {
                    let name: String = d["undef".len()..]
                        .trim_start()
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    if name.is_empty() {
                        continue;
                    }
                    (name, None)
                }
                _ => continue,
            };
            if is_dead(*line) {
                continue;
            }
            if let Some(group) = open.last_mut().filter(|g| !g.guard) {
                group.replaced.insert(name.clone());
            }
            steps.entry(name).or_default().push((
                *line,
                MacroStep::Set {
                    body,
                    arms: arms_of(&open),
                },
            ));
        }
        Self {
            names: steps
                .into_iter()
                .map(|(name, steps)| (name, NameTimeline::build(steps)))
                .collect(),
            directive_lines: directives.iter().map(|(line, _)| *line).collect(),
        }
    }

    /// How many of the file's directives come before `line`. Every name's
    /// directives are among them, so two lines at one position see the same
    /// [`ObjectMacroTimeline::in_force`] for every name: a caller asking the
    /// same question at many calls can answer it once per position. A file
    /// defining one name under thousands of `#ifdef` arms has every
    /// alternative in force at each call after them, and walking them all at
    /// each call is quadratic in the file.
    pub fn position(&self, line: usize) -> usize {
        self.directive_lines.partition_point(|&l| l < line)
    }

    /// Every name the file defines or undefines.
    pub fn names(&self) -> impl Iterator<Item = &String> {
        self.names.keys()
    }

    /// What `name` may stand for on `line` (from 1): the directives before
    /// it, each replacing the alternatives it overrides. A line past the end
    /// gives what the file leaves in force for whoever includes it.
    pub fn in_force(&self, name: &str, line: usize) -> InForce {
        #[cfg(test)]
        IN_FORCE_WALKS.with(|n| n.set(n.get() + 1));
        let Some(timeline) = self.names.get(name) else {
            return InForce {
                bodies: Vec::new(),
                inherits: true,
            };
        };
        let before = timeline.lines.partition_point(|&l| l < line);
        let mut top = if before == 0 {
            Some(0)
        } else {
            timeline.heads[before - 1]
        };
        let mut inherits = false;
        let mut bodies = Vec::new();
        while let Some(i) = top {
            let alternative = &timeline.alternatives[i];
            match &alternative.body {
                Some(body) => bodies.push(body.clone()),
                None => inherits = true,
            }
            top = alternative.below;
        }
        bodies.sort();
        bodies.dedup();
        InForce { bodies, inherits }
    }
}

/// Whether an invocation of `name` is one `{ ... }` block in every
/// configuration, reading the union of several tables (the project's and one
/// file's own): it has at least one definition, no table lists it as
/// conditional ([`collect_conditional_macro_names`]), and every definition is
/// function-like with a replacement list that is exactly one braced block.
/// valkey's `swapcode(TYPE, a, b, n) { ... }` qualifies; a
/// `do { ... } while (0)` or an `if` does not.
pub fn expands_to_block_everywhere(
    defs: &[&HashMap<String, Vec<MacroDefinition>>],
    conditional: &[&HashSet<String>],
    name: &str,
) -> bool {
    if conditional.iter().any(|c| c.contains(name)) {
        return false;
    }
    let mut alts = defs.iter().filter_map(|d| d.get(name)).flatten().peekable();
    alts.peek().is_some()
        && alts.all(|d| match d {
            MacroDefinition::Function { body, .. } => is_one_block(body),
            _ => false,
        })
}

/// Whether `body` is exactly one `{ ... }`: its first `{` closes at its last
/// byte. `body` is normalized, so no brace inside a literal or comment is read.
fn is_one_block(body: &str) -> bool {
    let body = body.trim();
    if !body.starts_with('{') || !body.ends_with('}') {
        return false;
    }
    let mut depth = 0usize;
    for (i, b) in body.bytes().enumerate() {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i == body.len() - 1;
                }
            }
            _ => {}
        }
    }
    false
}

/// `macro name -> index of the parameter it checks`, for every function-like
/// macro that, under every one of its definitions, returns only when that
/// parameter is true (see the module doc for exactly what qualifies).
pub fn abort_check_macros(
    defs: &HashMap<String, Vec<MacroDefinition>>,
    noreturn: &HashSet<String>,
) -> HashMap<String, usize> {
    let cx = Cx { defs, noreturn };
    let mut out = HashMap::new();
    for (name, alts) in defs {
        // `<assert.h>` always supplies the `NDEBUG`-strippable alternative.
        if name == "assert" {
            continue;
        }
        let mut checked: Option<usize> = None;
        let mut ok = !alts.is_empty();
        for def in alts {
            let MacroDefinition::Function { params, body } = def else {
                ok = false;
                break;
            };
            match cx.checked_param(body, params, 0) {
                Some(i) if checked.is_none_or(|c| c == i) => checked = Some(i),
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if let (true, Some(i)) = (ok, checked) {
            out.insert(name.clone(), i);
        }
    }
    out
}

/// The argument `stmt` checks, when `stmt` is an expression statement calling
/// one of `checks` (an [`abort_check_macros`] table): control passes the
/// statement only when that argument is true, in every configuration.
///
/// Anything else is `None`, and that includes every spelling of an
/// `NDEBUG`-strippable assert (`assert`, curl's `DEBUGASSERT`, hostap's
/// `WPA_ASSERT`), whatever its name suggests (ADR-0010 D5). A statement inside
/// a preprocessor wrapper is not looked into either: a check that only some
/// configurations compile guards nothing in the others.
pub fn abort_checked_argument<'a>(
    stmt: &tree_sitter::Node<'a>,
    source: &str,
    checks: &HashMap<String, usize>,
) -> Option<tree_sitter::Node<'a>> {
    if stmt.kind() != "expression_statement" {
        return None;
    }
    let call = stmt.named_child(0)?;
    if call.kind() != "call_expression" {
        return None;
    }
    let name = call
        .child_by_field_name("function")?
        .utf8_text(source.as_bytes())
        .ok()?;
    let &index = checks.get(name)?;
    call.child_by_field_name("arguments")?.named_child(index)
}

const MAX_DEPTH: usize = 8;

/// How a failure branch leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Exit {
    /// It may return.
    No,
    /// Only `__builtin_unreachable`: undefined behavior if reached, which a
    /// compiler may treat as an assumption. Not a check on its own.
    Assumed,
    /// A call that genuinely does not return.
    Real,
}

struct Cx<'a> {
    defs: &'a HashMap<String, Vec<MacroDefinition>>,
    noreturn: &'a HashSet<String>,
}

impl Cx<'_> {
    /// The parameter whose falsity `body` refuses to return from.
    fn checked_param(&self, body: &str, params: &[String], depth: usize) -> Option<usize> {
        let e = strip_void_cast(strip_group(body));
        if let Some(inner) = do_while_zero_body(e) {
            return self.statement_check(inner, params, depth);
        }
        if e.starts_with("if") && !is_ident_byte_at(e, 2) {
            return self.statement_check(e, params, depth);
        }
        if let Some((c, t, f)) = split_ternary(e) {
            let (i, positive) = self.polarity(c, params, depth)?;
            let (pass, fail) = if positive { (t, f) } else { (f, t) };
            return (is_noop(pass) && self.exits(fail, depth) == Exit::Real).then_some(i);
        }
        for (op, want) in [("||", true), ("&&", false)] {
            if let Some((l, r)) = split_top_level_binary(e, op) {
                let (i, positive) = self.polarity(l, params, depth)?;
                return (positive == want && self.exits(r, depth) == Exit::Real).then_some(i);
            }
        }
        None
    }

    /// `if (!C) FAIL` as the whole statement list (a `{ }` block holding only
    /// that `if` is the same thing).
    fn statement_check(&self, stmt: &str, params: &[String], depth: usize) -> Option<usize> {
        let s = strip_block(stmt.trim().trim_end_matches(';').trim());
        let rest = s.strip_prefix("if")?.trim_start();
        if !rest.starts_with('(') {
            return None;
        }
        let close = matching_close(rest, 0)?;
        let cond = &rest[1..close];
        let then = rest[close + 1..].trim();
        // An `else` would make the failure branch one of two alternatives.
        if contains_top_level_keyword(then, "else") {
            return None;
        }
        let (i, positive) = self.polarity(cond, params, depth)?;
        (!positive && self.exits(then, depth) == Exit::Real).then_some(i)
    }

    /// `(parameter index, positive)` when `e` is true exactly when that
    /// parameter is (positive) or is not (negative).
    fn polarity(&self, e: &str, params: &[String], depth: usize) -> Option<(usize, bool)> {
        if depth > MAX_DEPTH {
            return None;
        }
        let e = strip_group(e);
        if let Some(rest) = e.strip_prefix('!') {
            if !rest.starts_with('=') {
                let (i, p) = self.polarity(rest, params, depth + 1)?;
                return Some((i, !p));
            }
        }
        if let Some(i) = params.iter().position(|p| p == e) {
            return Some((i, true));
        }
        let (name, args) = whole_call(e)?;
        if name == "__builtin_expect" && args.len() == 2 {
            return self.polarity(&args[0], params, depth + 1);
        }
        // A macro that is its argument's truthiness under every definition
        // (`likely(x)`: `__builtin_expect(!!(x), 1)` or `(x)`).
        let alts = self.defs.get(name)?;
        let mut via: Option<(usize, bool)> = None;
        for def in alts {
            let MacroDefinition::Function { params: mp, body } = def else {
                return None;
            };
            if mp.len() != args.len() {
                return None;
            }
            let pol = self.polarity(body, mp, depth + 1)?;
            if via.is_some_and(|v| v != pol) {
                return None;
            }
            via = Some(pol);
        }
        let (j, pj) = via?;
        let (i, pi) = self.polarity(&args[j], params, depth + 1)?;
        Some((i, pi == pj))
    }

    /// Whether evaluating `e` unconditionally leaves.
    fn exits(&self, e: &str, depth: usize) -> Exit {
        if depth > MAX_DEPTH {
            return Exit::No;
        }
        let e = strip_void_cast(strip_group(e.trim().trim_end_matches(';').trim()));
        let parts: Vec<&str> = if e.starts_with('{') && e.ends_with('}') {
            split_top_level(&e[1..e.len() - 1], b';')
        } else {
            split_top_level(e, b',')
        };
        let mut reported = false;
        for part in parts {
            let part = strip_void_cast(strip_group(part.trim()));
            if part.is_empty() {
                continue;
            }
            let Some((name, _)) = whole_call(part) else {
                continue;
            };
            match self.callee_exits(name, depth + 1) {
                Exit::Real => return Exit::Real,
                Exit::Assumed if reported => return Exit::Real,
                Exit::Assumed => return Exit::Assumed,
                Exit::No => reported = true,
            }
        }
        Exit::No
    }

    fn callee_exits(&self, name: &str, depth: usize) -> Exit {
        if depth > MAX_DEPTH {
            return Exit::No;
        }
        match name {
            "__builtin_trap" => return Exit::Real,
            "__builtin_unreachable" => return Exit::Assumed,
            _ => {}
        }
        if let Some(alts) = self.defs.get(name) {
            // The weakest definition decides.
            let mut weakest = Exit::Real;
            for def in alts {
                let e = match def {
                    MacroDefinition::Object { body } => {
                        let b = strip_group(body);
                        if is_identifier(b) {
                            self.callee_exits(b, depth + 1)
                        } else {
                            Exit::No
                        }
                    }
                    MacroDefinition::Function { body, .. } => self.exits(body, depth + 1),
                    MacroDefinition::Opaque => Exit::No,
                };
                weakest = weakest.min(e);
            }
            return weakest;
        }
        if self.noreturn.contains(name) {
            Exit::Real
        } else {
            Exit::No
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing a `#define` line
// ---------------------------------------------------------------------------

fn parse_define(line: &str) -> Option<(String, MacroDefinition)> {
    let s = line.trim_start().strip_prefix('#')?.trim_start();
    let s = s.strip_prefix("define")?;
    if !s.starts_with(|c: char| c.is_whitespace()) {
        return None;
    }
    let s = s.trim_start();
    let name_len = s
        .char_indices()
        .find(|&(i, c)| !(c == '_' || c.is_ascii_alphanumeric()) || (i == 0 && c.is_ascii_digit()))
        .map_or(s.len(), |(i, _)| i);
    if name_len == 0 {
        return None;
    }
    let name = s[..name_len].to_string();
    let after = &s[name_len..];
    if !after.starts_with('(') {
        return Some(match normalize_body(after, &[]) {
            Some(body) => (name, MacroDefinition::Object { body }),
            None => (name, MacroDefinition::Opaque),
        });
    }
    let Some(close) = after.find(')') else {
        return Some((name, MacroDefinition::Opaque));
    };
    let mut params = Vec::new();
    for p in after[1..close].split(',') {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        if p.contains("...") || !is_identifier(p) {
            return Some((name, MacroDefinition::Opaque));
        }
        params.push(p.to_string());
    }
    match normalize_body(&after[close + 1..], &params) {
        Some(body) => Some((name, MacroDefinition::Function { params, body })),
        None => Some((name, MacroDefinition::Opaque)),
    }
}

/// The replacement list with comments removed, every string or character
/// literal replaced by `""`/`0` (so no delimiter inside one is ever read as
/// syntax), and each `#param` stringize replaced by `""`. `None` for token
/// paste (`##`) or a `#` that is not a stringize of a parameter.
fn normalize_body(raw: &str, params: &[String]) -> Option<String> {
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '/' if chars.get(i + 1) == Some(&'*') => {
                i += 2;
                while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                    i += 1;
                }
                i += 2;
                out.push(' ');
            }
            '/' if chars.get(i + 1) == Some(&'/') => break,
            '"' | '\'' => {
                i += 1;
                while i < chars.len() && chars[i] != c {
                    if chars[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
                out.push_str(if c == '"' { "\"\"" } else { "0" });
            }
            '#' => {
                if chars.get(i + 1) == Some(&'#') {
                    return None;
                }
                let mut j = i + 1;
                while j < chars.len() && chars[j].is_whitespace() {
                    j += 1;
                }
                let start = j;
                while j < chars.len() && (chars[j] == '_' || chars[j].is_ascii_alphanumeric()) {
                    j += 1;
                }
                let ident: String = chars[start..j].iter().collect();
                if !params.contains(&ident) {
                    return None;
                }
                out.push_str("\"\"");
                i = j;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some(out.trim().to_string())
}

// ---------------------------------------------------------------------------
// Expression-text helpers (over normalized bodies: no literals left to trip on)
// ---------------------------------------------------------------------------

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn is_ident_byte_at(s: &str, i: usize) -> bool {
    s.as_bytes()
        .get(i)
        .is_some_and(|&b| b == b'_' || b.is_ascii_alphanumeric())
}

/// Index of the bracket closing the one at byte `open`.
fn matching_close(s: &str, open: usize) -> Option<usize> {
    let mut depth = 0i32;
    for (i, b) in s.bytes().enumerate().skip(open) {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Strip parentheses that enclose the whole expression, repeatedly.
fn strip_group(s: &str) -> &str {
    let mut s = s.trim();
    while s.starts_with('(') && matching_close(s, 0) == Some(s.len() - 1) {
        s = s[1..s.len() - 1].trim();
    }
    s
}

/// Strip a leading `(void)` cast.
fn strip_void_cast(s: &str) -> &str {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix('(') {
        if let Some(rest) = rest.trim_start().strip_prefix("void") {
            if let Some(rest) = rest.trim_start().strip_prefix(')') {
                return strip_group(rest);
            }
        }
    }
    t
}

/// A `{ ... }` block reduced to its contents.
fn strip_block(s: &str) -> &str {
    let s = s.trim();
    if s.starts_with('{') && matching_close(s, 0) == Some(s.len() - 1) {
        s[1..s.len() - 1].trim().trim_end_matches(';').trim()
    } else {
        s
    }
}

fn is_noop(s: &str) -> bool {
    let s = strip_void_cast(strip_group(s));
    s.is_empty() || s == "0"
}

/// `do { BODY } while (0)` → `BODY`.
fn do_while_zero_body(s: &str) -> Option<&str> {
    let rest = s.strip_prefix("do")?;
    if is_ident_byte_at(s, 2) {
        return None;
    }
    let rest = rest.trim_start();
    if !rest.starts_with('{') {
        return None;
    }
    let close = matching_close(rest, 0)?;
    let tail = rest[close + 1..].trim().trim_end_matches(';').trim();
    let cond = tail.strip_prefix("while")?.trim();
    (strip_group(cond) == "0").then(|| &rest[1..close])
}

/// `name(args)` spanning the whole of `s`.
fn whole_call(s: &str) -> Option<(&str, Vec<String>)> {
    let s = s.trim();
    let open = s.find('(')?;
    let name = s[..open].trim();
    if !is_identifier(name) || matching_close(s, open) != Some(s.len() - 1) {
        return None;
    }
    let inner = &s[open + 1..s.len() - 1];
    let args = if inner.trim().is_empty() {
        Vec::new()
    } else {
        split_top_level(inner, b',')
            .into_iter()
            .map(|a| a.trim().to_string())
            .collect()
    };
    Some((name, args))
}

/// `s` split at `sep` outside any bracket.
fn split_top_level(s: &str, sep: u8) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut last = 0;
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            _ if b == sep && depth == 0 => {
                out.push(&s[last..i]);
                last = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[last..]);
    out
}

/// `C ? T : F` at the top level of `s`, splitting at the first `?` and its
/// matching `:`.
fn split_ternary(s: &str) -> Option<(&str, &str, &str)> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut q = None;
    let mut nested = 0i32;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'?' if depth == 0 => {
                if q.is_none() {
                    q = Some(i);
                } else {
                    nested += 1;
                }
            }
            b':' if depth == 0 && q.is_some() => {
                if nested == 0 {
                    let q = q.unwrap();
                    return Some((&s[..q], &s[q + 1..i], &s[i + 1..]));
                }
                nested -= 1;
            }
            _ => {}
        }
    }
    None
}

/// `L op R` at the top level, split at the first `op` (`||` or `&&`). Only
/// when no other top-level operator could bind looser: a comma or `?`
/// anywhere at the top level means the split is not the whole expression.
fn split_top_level_binary<'a>(s: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut at = None;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b',' | b'?' | b';' if depth == 0 => return None,
            _ if depth == 0 && at.is_none() && s.as_bytes()[i..].starts_with(op.as_bytes()) => {
                at = Some(i)
            }
            _ => {}
        }
    }
    let i = at?;
    // A second, different logical operator at the top level would change
    // grouping (`a || b && c`); refuse rather than guess.
    let other = if op == "||" { "&&" } else { "||" };
    if split_depth0_contains(s, other) {
        return None;
    }
    Some((&s[..i], &s[i + op.len()..]))
}

fn split_depth0_contains(s: &str, needle: &str) -> bool {
    let mut depth = 0i32;
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            _ if depth == 0 && s.as_bytes()[i..].starts_with(needle.as_bytes()) => return true,
            _ => {}
        }
    }
    false
}

fn contains_top_level_keyword(s: &str, kw: &str) -> bool {
    let mut depth = 0i32;
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            _ if depth == 0
                && s.as_bytes()[i..].starts_with(kw.as_bytes())
                && (i == 0 || !is_ident_byte_at(s, i - 1))
                && !is_ident_byte_at(s, i + kw.len()) =>
            {
                return true
            }
            _ => {}
        }
    }
    false
}

#[cfg(test)]
thread_local! {
    /// How many times [`ObjectMacroTimeline::in_force`] walked a name's
    /// alternatives on this thread.
    static IN_FORCE_WALKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// [`ObjectMacroTimeline::in_force`] walks on this thread since the last
/// call.
#[cfg(test)]
pub(crate) fn take_in_force_walks() -> usize {
    IN_FORCE_WALKS.with(|n| n.replace(0))
}
#[cfg(test)]
mod tests {
    use super::*;

    fn blocks(src: &str, name: &str) -> bool {
        let defs = collect_macro_definitions(src);
        let cond = collect_conditional_macro_names(src);
        expands_to_block_everywhere(&[&defs], &[&cond], name)
    }

    #[test]
    fn an_unconditional_block_macro_is_a_block() {
        let src = "#define SWAP(a, b) { int t = a; a = b; b = t; }\n";
        assert!(blocks(src, "SWAP"));
    }

    #[test]
    fn a_block_under_ifdef_is_not_a_block_everywhere() {
        let src = "#ifdef INLINE_MEMCPY\n# define memcpy(D,S,N) { copy(D,S,N); }\n#endif\n";
        assert!(collect_conditional_macro_names(src).contains("memcpy"));
        assert!(!blocks(src, "memcpy"));
    }

    #[test]
    fn an_include_guard_is_not_a_configuration() {
        let src = "#ifndef H_H\n#define H_H\n#define SWAP(a, b) { a = b; }\n#endif\n";
        assert!(collect_conditional_macro_names(src).is_empty());
        assert!(blocks(src, "SWAP"));
    }

    #[test]
    fn a_name_every_arm_defines_is_not_conditional() {
        let src = "#ifdef DEBUG\n#define CHECK(x) check(x)\n#elif defined(FAST)\n#define CHECK(x) fast(x)\n#else\n#define CHECK(x) ((void)(x))\n#endif\n";
        assert!(collect_conditional_macro_names(src).is_empty());
    }

    #[test]
    fn a_name_one_arm_leaves_undefined_is_conditional() {
        // No `#else`: a build without DEBUG has no CHECK.
        let lone = "#ifdef DEBUG\n#define CHECK(x) check(x)\n#endif\n";
        assert!(collect_conditional_macro_names(lone).contains("CHECK"));
        // An `#else` that defines it only when another name is set.
        let nested = "#ifdef DEBUG\n#define CHECK(x) check(x)\n#else\n#ifdef FAST\n#define CHECK(x) fast(x)\n#endif\n#endif\n";
        assert!(collect_conditional_macro_names(nested).contains("CHECK"));
        // An `#elif` chain with no `#else`.
        let elif = "#if A\n#define CHECK(x) a(x)\n#elif B\n#define CHECK(x) b(x)\n#endif\n";
        assert!(collect_conditional_macro_names(elif).contains("CHECK"));
    }

    #[test]
    fn a_nested_group_that_covers_its_arm_counts_for_the_arm() {
        let src = "#ifdef DEBUG\n#define CHECK(x) check(x)\n#else\n#ifdef FAST\n#define CHECK(x) fast(x)\n#else\n#define CHECK(x) ((void)(x))\n#endif\n#endif\n";
        assert!(collect_conditional_macro_names(src).is_empty());
    }

    #[test]
    fn a_dead_arm_is_not_a_configuration() {
        let src = "#if 0\n#define OLD 1\n#else\n#define CHECK(x) check(x)\n#endif\n";
        assert!(collect_conditional_macro_names(src).is_empty());
    }

    #[test]
    fn a_name_also_defined_unconditionally_is_not_conditional() {
        let src = "#define CHECK(x) check(x)\n#ifdef FAST\n#undef CHECK\n#define CHECK(x) fast(x)\n#endif\n";
        assert!(collect_conditional_macro_names(src).is_empty());
    }

    #[test]
    fn a_covering_group_inside_an_include_guard_is_not_conditional() {
        let src = "#ifndef H_H\n#define H_H\n#ifdef DEBUG\n#define CHECK(x) check(x)\n#else\n#define CHECK(x) ((void)(x))\n#endif\n#endif\n";
        assert!(collect_conditional_macro_names(src).is_empty());
    }

    #[test]
    fn a_define_in_a_dead_region_is_not_conditional() {
        let src = "#if 0\n#define SWAP(a, b) { a = b; }\n#endif\n";
        assert!(collect_conditional_macro_names(src).is_empty());
    }

    #[test]
    fn a_do_while_or_an_if_is_not_a_block() {
        assert!(!blocks("#define F(x) do { g(x); } while (0)\n", "F"));
        assert!(!blocks("#define F(x) if (x) { g(x); }\n", "F"));
        assert!(!blocks("#define F(x) { g(x); } { h(x); }\n", "F"));
    }

    fn checks(src: &str) -> HashMap<String, usize> {
        let defs = collect_macro_definitions(src);
        let noreturn: HashSet<String> = ["abort", "exit"].iter().map(|s| s.to_string()).collect();
        abort_check_macros(&defs, &noreturn)
    }

    const VALKEY: &str = r#"
#if __GNUC__ >= 5
#define valkey_unreachable __builtin_unreachable
#else
#define valkey_unreachable abort
#endif
#if __GNUC__ >= 3
#define likely(x) __builtin_expect(!!(x), 1)
#else
#define likely(x) (x)
#endif
#define serverAssertWithInfo(_c, _o, _e) \
    (likely(_e) ? (void)0 : (_serverAssertWithInfo(_c, _o, #_e, __FILE__, __LINE__), valkey_unreachable()))
#define serverAssert(_e) (likely(_e) ? (void)0 : (_serverAssert(#_e, __FILE__, __LINE__), valkey_unreachable()))
#define debugServerAssert(...) (server.enable_debug_assert ? serverAssert(__VA_ARGS__) : (void)0)
#define assert(_e) (likely((_e)) ? (void)0 : (_serverAssert(#_e, __FILE__, __LINE__), valkey_unreachable()))
#define ValkeyModule_Assert(_e) ((_e) ? (void)0 : (ValkeyModule__Assert(#_e, __FILE__, __LINE__), exit(1)))
"#;

    #[test]
    fn valkey_asserts_are_checks() {
        let m = checks(VALKEY);
        assert_eq!(m.get("serverAssert"), Some(&0));
        assert_eq!(m.get("serverAssertWithInfo"), Some(&2));
        assert_eq!(m.get("ValkeyModule_Assert"), Some(&0));
    }

    #[test]
    fn runtime_gated_and_assert_stay_neutral() {
        let m = checks(VALKEY);
        assert!(!m.contains_key("debugServerAssert"));
        assert!(!m.contains_key("assert"));
        assert!(!m.contains_key("likely"));
    }

    #[test]
    fn runtime_gate_is_not_a_check_even_when_not_variadic() {
        let src = "#define M(x) (g_on ? ((x) ? (void)0 : abort()) : (void)0)\n";
        assert!(checks(src).is_empty());
    }

    #[test]
    fn ndebug_arm_disqualifies() {
        let src = "#ifdef NDEBUG\n#define CHECK(x) ((void)0)\n#else\n#define CHECK(x) do { if (!(x)) abort(); } while (0)\n#endif\n";
        assert!(checks(src).is_empty());
        // The same macro with only the checking arm qualifies.
        let one = "#define CHECK(x) do { if (!(x)) abort(); } while (0)\n";
        assert_eq!(checks(one).get("CHECK"), Some(&0));
    }

    #[test]
    fn if_zero_arm_is_not_a_configuration() {
        let src =
            "#if 0\n#define CHECK(x) ((void)0)\n#endif\n#define CHECK(x) ((x) || (abort(), 0))\n";
        assert_eq!(checks(src).get("CHECK"), Some(&0));
    }

    #[test]
    fn assume_is_not_a_check() {
        let src = "#define ASSUME(x) do { if (!(x)) __builtin_unreachable(); } while (0)\n";
        assert!(checks(src).is_empty());
    }

    #[test]
    fn non_returning_fail_branch_required() {
        let src = "#define WARN_ON(x) ((x) ? (void)0 : report(#x))\n";
        assert!(checks(src).is_empty());
    }

    #[test]
    fn negated_forms() {
        let src =
            "#define A(x) (!(x) ? abort() : (void)0)\n#define B(x) (void)(!(x) && (exit(1), 0))\n";
        let m = checks(src);
        assert_eq!(m.get("A"), Some(&0));
        assert_eq!(m.get("B"), Some(&0));
    }

    #[test]
    fn if_with_else_is_not_a_check() {
        let src = "#define M(x) if (!(x)) abort(); else log()\n";
        assert!(checks(src).is_empty());
    }

    /// The bodies `name` may have on `line` of `src`, and whether a
    /// definition from before the file still stands there.
    fn in_force(src: &str, name: &str, line: usize) -> (Vec<String>, bool) {
        let found = ObjectMacroTimeline::of(src).in_force(name, line);
        (found.bodies, found.inherits)
    }

    fn bodies(list: &[&str]) -> Vec<String> {
        list.iter().map(|b| b.to_string()).collect()
    }

    /// Lines at one directive position see the same definitions of every
    /// name, and each directive starts a new position: across `#define`,
    /// `#undef`, `#ifdef` arms with and without `#else`, a nested group and
    /// an include guard, every line's answer for every name is the answer
    /// at the first line of its position.
    #[test]
    fn lines_at_one_position_see_the_same_definitions() {
        let src = "#ifndef GUARD_H\n#define GUARD_H\n\
            int a;\n#define M 1\nint b;\n\
            #ifdef X\n#define M 2\nint c;\n#else\n#undef M\n#endif\n\
            int d;\n\
            #ifdef Y\n#  ifdef Z\n#define N (M | 4)\n#  endif\n#define M 3\n#endif\n\
            int e;\nint f;\n#endif\nint g;\n";
        let timeline = ObjectMacroTimeline::of(src);
        let lines = src.lines().count() + 1;
        let mut first_at: HashMap<usize, usize> = HashMap::new();
        let mut positions = HashSet::new();
        for line in 1..=lines + 1 {
            let position = timeline.position(line);
            positions.insert(position);
            let first = *first_at.entry(position).or_insert(line);
            for name in ["M", "N", "GUARD_H", "UNSEEN"] {
                assert_eq!(
                    timeline.in_force(name, line),
                    timeline.in_force(name, first),
                    "{name} on line {line} against line {first}"
                );
            }
        }
        let directives = src
            .lines()
            .filter(|l| l.trim_start().starts_with('#'))
            .count();
        assert_eq!(positions.len(), directives + 1);
    }

    #[test]
    fn a_sequential_redefinition_replaces_the_earlier_body() {
        let src = "#define M KEY_WRITE\n#undef M\n#define M KEY_READ\nuse(M);\n";
        assert_eq!(in_force(src, "M", 4), (bodies(&["KEY_READ"]), false));
        assert_eq!(in_force(src, "M", 3), (bodies(&[]), false));
        assert_eq!(in_force(src, "M", 2), (bodies(&["KEY_WRITE"]), false));
        assert_eq!(in_force(src, "M", 1), (bodies(&[]), true));
    }

    #[test]
    fn the_arms_of_a_conditional_are_alternatives() {
        let src =
            "#ifdef X\n#define M A\n#elif Y\n#define M B\n#else\n#define M C\n#endif\nuse(M);\n";
        assert_eq!(in_force(src, "M", 8), (bodies(&["A", "B", "C"]), false));
        // Without an `#else`, a build takes no arm and keeps what came before.
        let src = "#ifdef X\n#define M A\n#elif Y\n#define M B\n#endif\nuse(M);\n";
        assert_eq!(in_force(src, "M", 6), (bodies(&["A", "B"]), true));
        // An arm that leaves the name alone keeps what came before too.
        let src = "#define M W\n#ifdef X\n#undef M\n#define M R\n#else\nint y;\n#endif\nuse(M);\n";
        assert_eq!(in_force(src, "M", 8), (bodies(&["R", "W"]), false));
        let src = "#define M A\n#ifdef X\n#undef M\n#define M B\n#endif\nuse(M);\n";
        assert_eq!(in_force(src, "M", 7), (bodies(&["A", "B"]), false));
        let src = "#ifdef X\n#define M B\n#endif\n#define M A\nuse(M);\n";
        assert_eq!(in_force(src, "M", 5), (bodies(&["A"]), false));
    }

    #[test]
    fn an_include_guard_is_not_a_build_alternative() {
        let src = "#ifndef H\n#define H\n#define M A\n#undef M\n#define M B\n#endif\n";
        assert_eq!(in_force(src, "M", usize::MAX), (bodies(&["B"]), false));
    }

    #[test]
    fn a_group_whose_every_arm_replaces_the_name_ends_what_came_before() {
        let src = "#ifdef X\n#undef M\n#define M KEY_READ\n#else\n#undef M\n#define M KEY_READ\n#endif\nuse(M);\n";
        assert_eq!(in_force(src, "M", 8), (bodies(&["KEY_READ"]), false));
        // Inside an outer arm, only the builds that take that arm lose it.
        let src = "#define M W\n#ifdef O\n#ifdef X\n#define M A\n#else\n#define M B\n#endif\nuse(M);\n#endif\nuse(M);\n";
        assert_eq!(in_force(src, "M", 8), (bodies(&["A", "B", "W"]), false));
        let src = "#ifdef O\n#ifdef X\n#define M A\n#else\n#define M B\n#endif\n#endif\nuse(M);\n";
        assert_eq!(in_force(src, "M", 8), (bodies(&["A", "B"]), true));
        // A nested group that replaces in every arm replaces for its arm.
        let src = "#ifdef X\n#ifdef Y\n#define M A\n#else\n#define M B\n#endif\n#else\n#define M C\n#endif\nuse(M);\n";
        assert_eq!(in_force(src, "M", 10), (bodies(&["A", "B", "C"]), false));
        // An arm the file proves dead is taken by no build.
        let src = "#if 0\nint z;\n#else\n#define M A\n#endif\nuse(M);\n";
        assert_eq!(in_force(src, "M", 6), (bodies(&["A"]), false));
    }

    #[test]
    fn a_default_value_block_is_not_an_include_guard() {
        let src =
            "int x;\n#ifndef APP_ACCESS\n#define APP_ACCESS KEY_READ\n#endif\nuse(APP_ACCESS);\n";
        assert_eq!(
            in_force(src, "APP_ACCESS", 5),
            (bodies(&["KEY_READ"]), true)
        );
        // Whatever the default is: a number, a null pointer, nothing.
        for (default, body) in [("1", "1"), ("(void *)0", "(void *)0"), ("", "")] {
            let src =
                format!("#include \"h.h\"\n#ifndef M\n#define M {default}\n#endif\nuse(M);\n");
            assert_eq!(in_force(&src, "M", 5), (bodies(&[body]), true), "{default}");
            // Even as the file's first directive, with code after it.
            let src = format!("#ifndef M\n#define M {default}\n#endif\nuse(M);\n");
            assert_eq!(in_force(&src, "M", 4), (bodies(&[body]), true), "{default}");
        }
        // A guard encloses the whole file, whatever its define gives the
        // name, and a licence comment before it changes nothing.
        let src = "#ifndef H\n#define H 1\n#define M A\n#endif\n";
        assert_eq!(in_force(src, "M", usize::MAX), (bodies(&["A"]), false));
        let src = "/* Copyright\n   Licence text\n*/\n// more\n#ifndef H\n#define H something\n#define M A\n#endif\n\n/* end */\n";
        assert_eq!(in_force(src, "M", usize::MAX), (bodies(&["A"]), false));
        let src = "#ifndef H\n#define H 1\n#define M A\n#endif\nint x;\n";
        assert_eq!(in_force(src, "M", usize::MAX), (bodies(&["A"]), true));
    }

    #[test]
    fn many_conditional_definitions_are_read_in_bounded_time() {
        let mut src = String::new();
        for i in 0..20_000 {
            src.push_str(&format!(
                "#ifdef Z{i}\n#define M K{i}\n#endif\nvoid g{i}(void) {{ f(M); }}\n"
            ));
        }
        let start = std::time::Instant::now();
        let timeline = ObjectMacroTimeline::of(&src);
        let mut total = 0;
        for i in (0..20_000).step_by(1000) {
            total += timeline.in_force("M", 4 * i + 4).bodies.len();
        }
        assert_eq!(
            total,
            (0..20_000).step_by(1000).map(|i| i + 1).sum::<usize>()
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn a_definition_after_the_line_leaves_the_earlier_one() {
        let src = "use(M);\n#undef M\n#define M KEY_READ\n";
        assert_eq!(in_force(src, "M", 1), (bodies(&[]), true));
    }
}
