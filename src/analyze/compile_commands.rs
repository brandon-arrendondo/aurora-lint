//! `compile_commands.json` ingestion — macro-expansion Phase 4 (task 187,
//! `docs/design/macro-expansion.md` §5(C)/§6).
//!
//! # Why this is not "approach C"
//!
//! §5(C) scoped Phase 4 as *"shell out to `cpp`/`clang -E`, parse the fully
//! expanded translation unit, map locations back via `#line`"*, and rejected it
//! as the default path because it explodes TU size, destroys the as-written
//! view the PRE-rules need, and makes every finding's location depend on
//! back-mapping fidelity.
//!
//! This module takes the cheap half of that idea and skips the expensive half.
//! sqc *already* has the machinery a compile DB would feed:
//!
//! - [`crate::analyze::prescan::resolve_includes`] already resolves `#include`
//!   directives transitively against a caller-supplied include-path list, and
//!   already harvests `macro_constants`, `macro_aliases` and `function_macros`
//!   out of every header it reaches.
//! - [`crate::analyze::macro_expand`] already expands those `function_macros`
//!   on demand, and is already wired into EXP33-C, EXP34-C, MEM30-C, MEM31-C
//!   and DCL31-C.
//!
//! The only reason §5(B) says sqc "cannot expand macros from unscanned system
//! headers" is that nothing ever *tells* it where those headers live. A compile
//! DB knows. So instead of preprocessing anything, this module reads the DB for
//! its `-I`/`-isystem`/`-iquote`/`-idirafter` search paths and its `-D`/`-U`
//! command-line macro state, and hands them to the pipeline that already
//! exists. No subprocess, no second parse, no `#line` back-mapping, and every
//! finding keeps the real source location it always had — because what gets
//! parsed does not change at all.
//!
//! # Invariants
//!
//! - **Opt-in and inert by default.** Nothing here runs unless the user passes
//!   `--compile-commands`. With the flag absent, analysis is byte-identical to
//!   before, which is the §4 "preserve the no-build-system model" constraint.
//! - **Gap-filling, never overriding.** Macros recovered from `-D` flags are
//!   merged with `or_insert` semantics *after* the source-derived prescan, so a
//!   real `#define` in real source always wins over a build flag. A build flag
//!   can only supply a name the tree never defined. This is the conservative
//!   direction: it can reveal a constant sqc previously treated as opaque, but
//!   it can never change the meaning of one it already resolved.
//! - **Paths are merged, not scoped per-file.** A compile DB is per-TU, but
//!   `resolve_includes` takes one global search list. Union-ing the entries is
//!   a deliberate approximation: it can only make *more* headers reachable, and
//!   header discovery is already best-effort (unresolved includes are skipped
//!   silently). It would be wrong for a project that compiles the same header
//!   name differently per target; no such case exists in the benchmark corpus.
//!
//! # Known gap
//!
//! A compile database lists the flags a build *passes*, so it does not contain
//! the compiler's own built-in system header directories (`/usr/include`, the
//! gcc internal include dir, …) — those are implicit. Macros from headers that
//! live only there, `<sys/queue.h>` being the §5(D) motivating example, are
//! therefore still out of reach. Closing that needs the compiler's default
//! search list (`cc -E -Wp,-v -`), which is why [`CompileDb::compilers`] is
//! recorded here. Deliberately left for a follow-up: it reintroduces a
//! subprocess, and the project-header win is worth measuring on its own first.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::context::ProjectContext;
use crate::parser::CParser;

/// One raw entry of a `compile_commands.json` array, per the LLVM JSON
/// Compilation Database spec. `file` is intentionally not deserialized: this
/// module unions every entry's flags into one search list rather than scoping
/// them per translation unit (see the module docs).
#[derive(Debug, Deserialize)]
struct RawEntry {
    /// Working directory the command was run from. Relative `-I` paths in this
    /// entry resolve against it.
    directory: String,
    /// The command as a single shell string (`command` form).
    #[serde(default)]
    command: Option<String>,
    /// The command already tokenized (`arguments` form). Preferred when both
    /// are present, since it needs no shell-quoting guesswork.
    #[serde(default)]
    arguments: Option<Vec<String>>,
}

/// A command-line macro definition recovered from a `-D` flag, kept in the
/// spelling a `#define` directive would use.
///
/// `spelling` is the whole left-hand side including any parameter list, so a
/// function-like `-D'MAX(a,b)=((a)>(b)?(a):(b))'` round-trips through
/// [`CompileDb::define_directives`] as a real function-like `#define` that
/// [`crate::analyze::macro_expand`] can then expand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLineDefine {
    /// Macro name, plus its parameter list for a function-like macro
    /// (e.g. `FOO` or `MAX(a,b)`).
    pub spelling: String,
    /// Replacement text. Empty for a bare `-DFOO`, which C defines as `1`.
    pub body: String,
}

impl CommandLineDefine {
    /// The bare macro name, with any parameter list stripped.
    pub fn name(&self) -> &str {
        match self.spelling.find('(') {
            Some(i) => &self.spelling[..i],
            None => &self.spelling,
        }
    }
}

/// Include search paths and command-line macro state distilled from a
/// `compile_commands.json`.
#[derive(Debug, Clone, Default)]
pub struct CompileDb {
    /// Absolute include search paths, first-seen order preserved so the search
    /// order of the original build is approximated.
    pub include_paths: Vec<String>,
    /// Surviving `-D` definitions, in first-seen order. Names later `-U`'d
    /// anywhere in the database are already removed.
    pub defines: Vec<CommandLineDefine>,
    /// Number of entries read from the database.
    pub entry_count: usize,
    /// Compiler executables named by the entries (`arguments[0]` / the first
    /// word of `command`), deduplicated. Used to locate the built-in system
    /// header directories a compile DB never lists.
    pub compilers: Vec<String>,
}

impl CompileDb {
    /// Read and distill a `compile_commands.json`.
    ///
    /// Entries that cannot be understood are skipped rather than failing the
    /// load: a compile DB routinely contains assembler or linker steps with no
    /// C flags at all, and a partial DB is still useful. Only an unreadable or
    /// malformed *file* is an error.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read compile database: {}", path.display()))?;
        let entries: Vec<RawEntry> = serde_json::from_str(&text).with_context(|| {
            format!(
                "Failed to parse {} as a JSON compilation database (expected an array of \
                 {{directory, file, command|arguments}} objects)",
                path.display()
            )
        })?;
        Ok(Self::from_entries(&entries))
    }

    fn from_entries(entries: &[RawEntry]) -> Self {
        let mut db = CompileDb {
            entry_count: entries.len(),
            ..Default::default()
        };

        let mut seen_paths: HashSet<String> = HashSet::new();
        let mut seen_compilers: HashSet<String> = HashSet::new();
        // -U anywhere in the database wins over -D anywhere in it. Applied as a
        // final filter because a DB is unordered with respect to any one TU, so
        // there is no meaningful "later flag wins" to honor across entries.
        let mut undefined: HashSet<String> = HashSet::new();
        let mut seen_defines: HashSet<String> = HashSet::new();

        for entry in entries {
            let argv = match (&entry.arguments, &entry.command) {
                (Some(args), _) => args.clone(),
                (None, Some(cmd)) => split_command(cmd),
                (None, None) => continue,
            };
            if argv.is_empty() {
                continue;
            }
            if seen_compilers.insert(argv[0].clone()) {
                db.compilers.push(argv[0].clone());
            }

            let base = Path::new(&entry.directory);
            for flag in parse_flags(&argv) {
                match flag {
                    Flag::Include(dir) => {
                        let abs = absolutize(base, &dir);
                        let s = abs.to_string_lossy().to_string();
                        if seen_paths.insert(s.clone()) {
                            db.include_paths.push(s);
                        }
                    }
                    Flag::Define(spelling, body) => {
                        if seen_defines.insert(spelling.clone()) {
                            db.defines.push(CommandLineDefine { spelling, body });
                        }
                    }
                    Flag::Undefine(name) => {
                        undefined.insert(name);
                    }
                }
            }
        }

        if !undefined.is_empty() {
            db.defines.retain(|d| !undefined.contains(d.name()));
        }
        db
    }

    /// Include search paths that do not exist on this filesystem.
    ///
    /// A compilation database records **absolute** paths from the machine that
    /// ran the build. Moving one between machines (or generating it in a
    /// throwaway clone, or in a container) leaves `-I` paths pointing at
    /// directories that are not here.
    ///
    /// This matters because the failure is otherwise *silent*:
    /// [`super::prescan::resolve_includes`] skips an `#include` it cannot
    /// resolve rather than erroring, which is correct for its normal
    /// best-effort job but means a wholly stale database degrades into an
    /// expensive no-op that still looks like it worked. Callers should surface
    /// this to the user.
    pub fn missing_include_paths(&self) -> Vec<&str> {
        self.include_paths
            .iter()
            .filter(|p| !Path::new(p).is_dir())
            .map(|p| p.as_str())
            .collect()
    }

    /// Render the recovered `-D` flags as C preprocessor source.
    ///
    /// A bare `-DFOO` becomes `#define FOO 1`, matching the C standard's
    /// treatment of a definition with no replacement list on the command line.
    ///
    /// Emitting real directives — rather than hand-populating the context maps
    /// — is deliberate: it means the existing collectors
    /// ([`super::const_eval::collect_macro_constants`],
    /// [`super::const_eval::collect_macro_aliases`],
    /// [`super::macro_expand::collect_function_macros`]) do the interpreting,
    /// so command-line macros get exactly the same constant folding, alias
    /// resolution and function-like handling as macros written in a header. No
    /// second implementation of `#define` semantics to keep in sync.
    pub fn define_directives(&self) -> String {
        let mut out = String::new();
        for d in &self.defines {
            let body = if d.body.is_empty() { "1" } else { &d.body };
            out.push_str("#define ");
            out.push_str(&d.spelling);
            out.push(' ');
            out.push_str(body);
            out.push('\n');
        }
        out
    }

    /// Merge the command-line macro state into `context`, filling only names
    /// the source-derived prescan did not already define.
    ///
    /// Call this *after* prescan and `#include` resolution so real definitions
    /// take precedence — see the "gap-filling, never overriding" invariant in
    /// the module docs. Returns the number of macro names newly contributed.
    pub fn merge_defines_into(&self, context: &mut ProjectContext) -> Result<usize> {
        if self.defines.is_empty() {
            return Ok(0);
        }
        let source = self.define_directives();

        let mut parser = CParser::new()?;
        let (tree, source) = parser.parse_source(&source)?;
        let root = tree.root_node();

        let mut added = 0usize;

        for (name, value) in super::const_eval::collect_macro_constants(&root, &source) {
            if let std::collections::hash_map::Entry::Vacant(e) =
                context.macro_constants.entry(name)
            {
                e.insert(value);
                added += 1;
            }
        }
        for (name, target) in super::const_eval::collect_macro_aliases(&root, &source) {
            if let std::collections::hash_map::Entry::Vacant(e) = context.macro_aliases.entry(name)
            {
                e.insert(target);
                added += 1;
            }
        }
        for (name, m) in super::macro_expand::collect_function_macros(&root, &source) {
            if let std::collections::hash_map::Entry::Vacant(e) =
                context.function_macros.entry(name)
            {
                e.insert(m);
                added += 1;
            }
        }

        Ok(added)
    }
}

/// A recognized compiler flag. Everything else in the command line is ignored.
#[derive(Debug, PartialEq, Eq)]
enum Flag {
    /// A header search directory, exactly as spelled on the command line.
    Include(String),
    /// `-D<spelling>[=<body>]`.
    Define(String, String),
    /// `-U<name>`.
    Undefine(String),
}

/// Flags whose directory argument may be attached (`-Idir`) or separate
/// (`-I dir`). `-I` is by far the common one; the others appear in
/// hand-written and cross-compilation builds.
const DIR_FLAGS: &[&str] = &["-I", "-isystem", "-iquote", "-idirafter"];

/// Extract the include/define/undefine flags from one tokenized command line.
fn parse_flags(argv: &[String]) -> Vec<Flag> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        i += 1;

        if let Some(rest) = arg.strip_prefix("-D") {
            if let Some(f) = define_flag(rest, argv, &mut i) {
                out.push(f);
            }
            continue;
        }
        if let Some(rest) = arg.strip_prefix("-U") {
            let name = take_value(rest, argv, &mut i);
            if let Some(name) = name {
                if !name.is_empty() {
                    out.push(Flag::Undefine(name));
                }
            }
            continue;
        }
        // Longest-prefix first so `-idirafter` is not shadowed by a shorter
        // flag sharing its prefix.
        let mut matched: Option<&str> = None;
        for f in DIR_FLAGS {
            if arg.starts_with(f) && matched.is_none_or(|m: &str| f.len() > m.len()) {
                matched = Some(f);
            }
        }
        if let Some(f) = matched {
            let rest = &arg[f.len()..];
            // `-isystem=dir` (clang tolerates the `=` form for the long flags).
            let rest = rest.strip_prefix('=').unwrap_or(rest);
            if let Some(dir) = take_value(rest, argv, &mut i) {
                if !dir.is_empty() {
                    out.push(Flag::Include(dir));
                }
            }
        }
    }
    out
}

/// Resolve a flag value that is either attached to the flag or the next argv
/// token. Advances `i` past the token when the separate form is used.
fn take_value(attached: &str, argv: &[String], i: &mut usize) -> Option<String> {
    if !attached.is_empty() {
        return Some(attached.to_string());
    }
    let next = argv.get(*i)?;
    *i += 1;
    Some(next.clone())
}

/// Build a [`Flag::Define`] from the text following `-D`, handling both
/// `-DNAME=VALUE` and the separate `-D NAME=VALUE` form.
fn define_flag(attached: &str, argv: &[String], i: &mut usize) -> Option<Flag> {
    let text = take_value(attached, argv, i)?;
    if text.is_empty() {
        return None;
    }
    // Split on the first `=`, which for a function-like macro necessarily
    // follows the parameter list: `MAX(a,b)=...` has no `=` inside `(a,b)`
    // because a parameter list is only identifiers and commas.
    let (spelling, body) = match text.find('=') {
        Some(eq) => (text[..eq].to_string(), text[eq + 1..].to_string()),
        None => (text, String::new()),
    };
    if spelling.is_empty() {
        return None;
    }
    Some(Flag::Define(spelling, body))
}

/// Resolve `dir` against the entry's working directory, leaving absolute paths
/// alone. The result is not canonicalized: a compile DB can name directories
/// that no longer exist, and `resolve_includes` already tolerates a search path
/// that does not resolve.
fn absolutize(base: &Path, dir: &str) -> PathBuf {
    let p = Path::new(dir);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

/// Split a `command` string into argv, honoring POSIX-ish single quotes, double
/// quotes and backslash escapes.
///
/// This exists because the `command` form of the compilation database stores a
/// shell string rather than a token list. Builds that quote nontrivially
/// (`-DVERSION=\"1.2\"`, paths with spaces) are common enough that a naive
/// `split_whitespace` mangles them.
fn split_command(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut has_token = false;
    let mut chars = cmd.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next) = chars.next() {
                    cur.push(next);
                    has_token = true;
                }
            }
            '\'' => {
                has_token = true;
                for c in chars.by_ref() {
                    if c == '\'' {
                        break;
                    }
                    cur.push(c);
                }
            }
            '"' => {
                has_token = true;
                while let Some(c) = chars.next() {
                    match c {
                        '"' => break,
                        // Inside double quotes only these are escapable; a
                        // backslash before anything else is literal.
                        '\\' => match chars.peek() {
                            Some('"') | Some('\\') | Some('$') | Some('`') => {
                                cur.push(chars.next().unwrap_or_default());
                            }
                            _ => cur.push('\\'),
                        },
                        _ => cur.push(c),
                    }
                }
            }
            c if c.is_whitespace() => {
                if has_token {
                    out.push(std::mem::take(&mut cur));
                    has_token = false;
                }
            }
            _ => {
                cur.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_attached_and_separate_include_flags() {
        let flags = parse_flags(&argv(&["cc", "-Iinc", "-I", "other", "-c", "a.c"]));
        assert_eq!(
            flags,
            vec![Flag::Include("inc".into()), Flag::Include("other".into()),]
        );
    }

    #[test]
    fn parses_long_include_flag_forms() {
        let flags = parse_flags(&argv(&[
            "cc",
            "-isystem",
            "/usr/local/include",
            "-iquote=q",
            "-idirafter",
            "after",
        ]));
        assert_eq!(
            flags,
            vec![
                Flag::Include("/usr/local/include".into()),
                Flag::Include("q".into()),
                Flag::Include("after".into()),
            ]
        );
    }

    #[test]
    fn parses_define_forms() {
        let flags = parse_flags(&argv(&["cc", "-DFOO", "-DBAR=2", "-D", "BAZ=3"]));
        assert_eq!(
            flags,
            vec![
                Flag::Define("FOO".into(), String::new()),
                Flag::Define("BAR".into(), "2".into()),
                Flag::Define("BAZ".into(), "3".into()),
            ]
        );
    }

    #[test]
    fn function_like_define_keeps_parameter_list_in_spelling() {
        let flags = parse_flags(&argv(&["cc", "-DMAX(a,b)=((a)>(b)?(a):(b))"]));
        assert_eq!(
            flags,
            vec![Flag::Define("MAX(a,b)".into(), "((a)>(b)?(a):(b))".into())]
        );
        let d = CommandLineDefine {
            spelling: "MAX(a,b)".into(),
            body: "((a)>(b)?(a):(b))".into(),
        };
        assert_eq!(d.name(), "MAX");
    }

    #[test]
    fn bare_define_renders_as_one() {
        let db = CompileDb {
            defines: vec![CommandLineDefine {
                spelling: "FOO".into(),
                body: String::new(),
            }],
            ..Default::default()
        };
        assert_eq!(db.define_directives(), "#define FOO 1\n");
    }

    #[test]
    fn undefine_removes_a_define_from_any_entry() {
        let entries = vec![
            RawEntry {
                directory: "/p".into(),
                command: Some("cc -DFOO=1 -DKEEP=2 -c a.c".into()),
                arguments: None,
            },
            RawEntry {
                directory: "/p".into(),
                command: Some("cc -UFOO -c b.c".into()),
                arguments: None,
            },
        ];
        let db = CompileDb::from_entries(&entries);
        let names: Vec<&str> = db.defines.iter().map(|d| d.name()).collect();
        assert_eq!(names, vec!["KEEP"]);
    }

    #[test]
    fn relative_include_paths_resolve_against_entry_directory() {
        let entries = vec![RawEntry {
            directory: "/proj/build".into(),
            command: Some("cc -I../src -I/abs/inc -c a.c".into()),
            arguments: None,
        }];
        let db = CompileDb::from_entries(&entries);
        assert_eq!(db.include_paths, vec!["/proj/build/../src", "/abs/inc"]);
    }

    #[test]
    fn include_paths_dedupe_preserving_first_seen_order() {
        let entries = vec![
            RawEntry {
                directory: "/p".into(),
                command: Some("cc -Ia -Ib -c a.c".into()),
                arguments: None,
            },
            RawEntry {
                directory: "/p".into(),
                command: Some("cc -Ib -Ic -c b.c".into()),
                arguments: None,
            },
        ];
        let db = CompileDb::from_entries(&entries);
        assert_eq!(db.include_paths, vec!["/p/a", "/p/b", "/p/c"]);
        assert_eq!(db.entry_count, 2);
    }

    #[test]
    fn arguments_form_wins_over_command_form() {
        let entries = vec![RawEntry {
            directory: "/p".into(),
            command: Some("cc -Ifrom_command -c a.c".into()),
            arguments: Some(argv(&["cc", "-Ifrom_arguments", "-c", "a.c"])),
        }];
        let db = CompileDb::from_entries(&entries);
        assert_eq!(db.include_paths, vec!["/p/from_arguments"]);
    }

    #[test]
    fn records_distinct_compilers() {
        let entries = vec![
            RawEntry {
                directory: "/p".into(),
                command: Some("/usr/bin/cc -c a.c".into()),
                arguments: None,
            },
            RawEntry {
                directory: "/p".into(),
                command: Some("/usr/bin/cc -c b.c".into()),
                arguments: None,
            },
            RawEntry {
                directory: "/p".into(),
                command: Some("arm-none-eabi-gcc -c c.c".into()),
                arguments: None,
            },
        ];
        let db = CompileDb::from_entries(&entries);
        assert_eq!(db.compilers, vec!["/usr/bin/cc", "arm-none-eabi-gcc"]);
    }

    #[test]
    fn split_command_handles_quotes_and_escapes() {
        assert_eq!(
            split_command(r#"cc -DS=\"hi\" -I"/a b" -DT='x y' -c a.c"#),
            argv(&["cc", r#"-DS="hi""#, "-I/a b", "-DT=x y", "-c", "a.c"])
        );
    }

    #[test]
    fn split_command_ignores_repeated_whitespace() {
        assert_eq!(
            split_command("  cc   -c\ta.c  "),
            argv(&["cc", "-c", "a.c"])
        );
    }

    #[test]
    fn entries_without_a_command_are_skipped_not_fatal() {
        let entries = vec![
            RawEntry {
                directory: "/p".into(),
                command: None,
                arguments: None,
            },
            RawEntry {
                directory: "/p".into(),
                command: Some("cc -Iinc -c a.c".into()),
                arguments: None,
            },
        ];
        let db = CompileDb::from_entries(&entries);
        assert_eq!(db.include_paths, vec!["/p/inc"]);
    }

    #[test]
    fn merge_defines_does_not_override_source_derived_macros() {
        let mut ctx = ProjectContext::new();
        ctx.macro_constants.insert("BUFSZ".into(), 64);

        let db = CompileDb {
            defines: vec![
                CommandLineDefine {
                    spelling: "BUFSZ".into(),
                    body: "999".into(),
                },
                CommandLineDefine {
                    spelling: "NEWSZ".into(),
                    body: "16".into(),
                },
            ],
            ..Default::default()
        };
        db.merge_defines_into(&mut ctx).unwrap();

        assert_eq!(ctx.macro_constants.get("BUFSZ"), Some(&64));
        assert_eq!(ctx.macro_constants.get("NEWSZ"), Some(&16));
    }

    #[test]
    fn merge_defines_contributes_function_like_macros() {
        let mut ctx = ProjectContext::new();
        let db = CompileDb {
            defines: vec![CommandLineDefine {
                spelling: "SQUARE(x)".into(),
                body: "((x)*(x))".into(),
            }],
            ..Default::default()
        };
        db.merge_defines_into(&mut ctx).unwrap();
        assert!(ctx.function_macros.contains_key("SQUARE"));
    }

    /// End-to-end: the whole point of the feature. A header reachable *only*
    /// via a `-I` from the compile database, included with angle brackets from
    /// a directory the sibling-header prescan would never look in, must end up
    /// contributing its macros to the project context — which is what makes
    /// them expandable by `macro_expand` and resolvable by `const_eval`.
    #[test]
    fn compile_db_include_path_brings_header_macros_into_context() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("vendor/inc")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("vendor/inc/vlib.h"),
            "#define VBUF_LEN 8\n#define VZERO(p) ((p)->a = 0)\n",
        )
        .unwrap();
        let c_file = root.join("src/a.c");
        // Angle-bracket include of a non-sibling header: unreachable without
        // the search path the compile database supplies.
        std::fs::write(&c_file, "#include <vlib.h>\nint f(void) { return 0; }\n").unwrap();

        let db_path = root.join("compile_commands.json");
        std::fs::write(
            &db_path,
            format!(
                r#"[{{"directory":"{d}","file":"{f}","command":"cc -Ivendor/inc -c src/a.c"}}]"#,
                d = root.display(),
                f = c_file.display(),
            ),
        )
        .unwrap();

        let db = CompileDb::load(&db_path).unwrap();
        assert_eq!(db.include_paths.len(), 1);

        let mut ctx = ProjectContext::new();
        // Baseline: nothing knows about the vendored header yet.
        assert!(!ctx.macro_constants.contains_key("VBUF_LEN"));

        super::super::prescan::resolve_includes(
            &[c_file.to_string_lossy().to_string()],
            &db.include_paths,
            &mut ctx,
            None,
            false,
        )
        .unwrap();

        assert_eq!(
            ctx.macro_constants.get("VBUF_LEN"),
            Some(&8),
            "compile-database -I path should make the vendored header's constants resolvable"
        );
        assert!(
            ctx.function_macros.contains_key("VZERO"),
            "compile-database -I path should make the vendored header's function-like macros expandable"
        );
    }

    #[test]
    fn missing_include_paths_flags_only_absent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let present = dir.path().to_string_lossy().to_string();
        let db = CompileDb {
            include_paths: vec![present.clone(), "/definitely/not/here".into()],
            ..Default::default()
        };
        assert_eq!(db.missing_include_paths(), vec!["/definitely/not/here"]);
    }

    #[test]
    fn merge_defines_is_a_noop_without_defines() {
        let mut ctx = ProjectContext::new();
        let db = CompileDb::default();
        assert_eq!(db.merge_defines_into(&mut ctx).unwrap(), 0);
        assert!(ctx.macro_constants.is_empty());
    }
}
