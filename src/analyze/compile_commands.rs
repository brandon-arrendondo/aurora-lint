//! `compile_commands.json` ingestion — macro-expansion Phase 4 (
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
//! aurora-lint *already* has the machinery a compile DB would feed:
//!
//! - [`crate::analyze::prescan::resolve_includes`] already resolves `#include`
//!   directives transitively against a caller-supplied include-path list, and
//!   already harvests `macro_constants`, `macro_aliases` and `function_macros`
//!   out of every header it reaches.
//! - [`crate::analyze::macro_expand`] already expands those `function_macros`
//!   on demand, and is already wired into EXP33-C, EXP34-C, MEM30-C, MEM31-C
//!   and DCL31-C.
//!
//! The only reason §5(B) says aurora-lint "cannot expand macros from unscanned system
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
//!   direction: it can reveal a constant aurora-lint previously treated as opaque, but
//!   it can never change the meaning of one it already resolved.
//! - **Paths are merged, not scoped per-file.** A compile DB is per-TU, but
//!   `resolve_includes` takes one global search list. Union-ing the entries is
//!   a deliberate approximation: it can only make *more* headers reachable, and
//!   header discovery is already best-effort (unresolved includes are skipped
//!   silently). It would be wrong for a project that compiles the same header
//!   name differently per target; no such case exists in the benchmark corpus.
//!
//! # MSVC command lines
//!
//! An entry whose driver is MSVC-like (`cl` or `clang-cl`, also behind a
//! compiler launcher such as `sccache`, or any driver given `--driver-mode=cl`,
//! even from a response file) is read with cl.exe's own syntax: every option may be
//! spelled with `/` or `-`, so `/DNAME=1`, `/D NAME`, `/Ipath`, `/I path`,
//! `/UNAME` and `/FIheader.h` (forced include, resolved before any header a
//! source includes, in command-line order) are recognised alongside
//! `-D`/`-I`, as are clang-cl's `/imsvc` and cl's `/external:I` system-header
//! directories. `/DNAME#VALUE` is cl's alternative to `=`, everything after
//! `/link` belongs to the linker, and everything after clang-cl's `--` is an
//! input file. The `/` spellings are deliberately *not*
//! recognised for any other driver: a POSIX absolute path such as
//! `/Users/me/a.c` or `/Include/x.c` would otherwise read as `/U` or `/I`.
//!
//! A `command` string is split with the MSVC C runtime's rules (backslashes are
//! literal unless they precede a `"`) when its first word is a Windows path or
//! an `.exe`, since that is the quoting the build that wrote it used; the POSIX
//! rules would turn `C:\src\inc` into `C:srcinc`. `@file` response files, which
//! cl builds use to stay under the command-length limit, are expanded in place
//! for either driver.
//!
//! # Known gap
//!
//! A compile database lists the flags a build *passes*, so it does not contain
//! the compiler's own built-in system header directories (`/usr/include`, the
//! gcc internal include dir, …) — those are implicit. Macros from headers that
//! live only there, `<sys/queue.h>` being the §5(D) motivating example, are
//! therefore still out of reach. Closing that needs the compiler's default
//! search list (`cc -E -Wp,-v -`), which is why [`compile_commands::CompileDb::compilers`] is
//! recorded here. Deliberately left for a follow-up: it reintroduces a
//! subprocess, and the project-header win is worth measuring on its own first.

use anyhow::{Context, Result};
use lang_parsing_substrate::PlatformAssumptions;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::context::ProjectContext;
use crate::parser::CParser;

/// One raw entry of a `compile_commands.json` array, per the LLVM JSON
/// Compilation Database spec. `file` is read only to record which translation
/// units the build compiles; flags are still unioned across entries rather
/// than scoped per TU (see the module docs).
#[derive(Debug, Deserialize)]
struct RawEntry {
    /// Working directory the command was run from. Relative `-I` paths in this
    /// entry resolve against it.
    directory: String,
    /// The translation unit this entry compiles. Not used to scope flags —
    /// the module unions them (see the module docs) — but recorded so the
    /// scan can tell which sources the declared configuration actually builds
    /// ([`CompileDb::uncovered_sources`]).
    #[serde(default)]
    file: Option<String>,
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
    /// Names `-U`'d anywhere in the database, first-seen order. Kept, rather
    /// than only used as the filter above, because "this build undefines X" is
    /// a *positive* fact about the configuration: it is what makes an
    /// `#ifdef X` arm dead rather than merely unproven
    /// ([`Self::declared_macro_state`]).
    pub undefines: Vec<String>,
    /// Headers the build force-includes into every translation unit (cl's
    /// `/FI`), first-seen order. Absolute when the file exists relative to the
    /// entry's directory, otherwise as spelled, so the include search paths
    /// can still find it -- exactly how cl looks one up.
    pub forced_includes: Vec<String>,
    /// Number of entries read from the database.
    pub entry_count: usize,
    /// Compiler executables named by the entries (`arguments[0]` / the first
    /// word of `command`), deduplicated. Used to locate the built-in system
    /// header directories a compile DB never lists.
    pub compilers: Vec<String>,
    /// Absolute paths of the translation units the database compiles — the
    /// source files that *are* the declared configuration. A database lists
    /// compiled TUs only, so this never contains a header.
    pub configured_sources: HashSet<String>,
    /// Each entry's working directory, absolute, first-seen order: where the
    /// build ran. An include directory inside one of these and outside the
    /// scanned tree is the build's own output (`generated_headers`).
    pub entry_directories: Vec<String>,
    /// Whether any entry was built by cl or clang-cl. Such a build looks
    /// `#include` names up the way Windows does, ignoring case, so unless the
    /// settings say otherwise the scan does too.
    pub msvc: bool,
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
        let mut seen_forced: HashSet<String> = HashSet::new();
        let mut seen_dirs: HashSet<String> = HashSet::new();

        for entry in entries {
            let base = Path::new(&entry.directory);
            if seen_dirs.insert(entry.directory.clone()) {
                db.entry_directories.push(entry.directory.clone());
            }
            let argv = match (&entry.arguments, &entry.command) {
                (Some(args), _) => args.clone(),
                (None, Some(cmd)) => split_command_for_host(cmd),
                (None, None) => continue,
            };
            if argv.is_empty() {
                continue;
            }
            if seen_compilers.insert(argv[0].clone()) {
                db.compilers.push(argv[0].clone());
            }
            let mut msvc = is_msvc_driver(&argv);
            let mut expanded = expand_response_files(argv.clone(), base, msvc);
            // `--driver-mode=cl` may itself sit in a response file; the files
            // are then re-read with cl's quoting.
            if !msvc && is_msvc_driver(&expanded) {
                msvc = true;
                expanded = expand_response_files(argv, base, msvc);
            }
            let argv = expanded;
            db.msvc |= msvc;

            if let Some(file) = &entry.file {
                db.configured_sources
                    .insert(real_path(&absolutize(base, file)));
            }
            for flag in parse_flags(&argv, msvc) {
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
                        if undefined.insert(name.clone()) {
                            db.undefines.push(name);
                        }
                    }
                    Flag::ForcedInclude(header) => {
                        let abs = absolutize(base, &header);
                        let s = if abs.is_file() {
                            abs.to_string_lossy().to_string()
                        } else {
                            header
                        };
                        if seen_forced.insert(s.clone()) {
                            db.forced_includes.push(s);
                        }
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

    /// The build's macro state as a definedness table: every surviving `-D`
    /// name defined, every `-U` name undefined.
    ///
    /// This is the same `-D`/`-U` state [`Self::define_directives`] renders,
    /// read for a different question. `define_directives` answers "what does
    /// this name expand to", which only matters for a name some rule evaluates;
    /// this answers "is this name defined", which decides which `#if` arm a
    /// collector may take a definition from at all
    /// ([`super::dead_regions::declare_scan_profile`]). A bare `-DFOO` and
    /// `-DFOO=0` are both *defined* here — `#ifdef FOO` tests definedness, not
    /// value — while `-UFOO` is the only thing that asserts the negative.
    ///
    /// Values are deliberately dropped: the substrate's dead-region scanner
    /// recognises `#ifdef`/`#ifndef`/`defined(X)`, not arithmetic `#if X > 2`,
    /// so a value here would be recorded and never read.
    pub fn declared_macro_state(&self) -> PlatformAssumptions {
        let mut state = PlatformAssumptions::new();
        for d in &self.defines {
            state.insert(d.name().to_string(), true);
        }
        // -U already filtered `defines`, so these cannot collide.
        for name in &self.undefines {
            state.insert(name.clone(), false);
        }
        state
    }

    /// Scanned `.c` files the database does not compile — sources outside the
    /// declared configuration.
    ///
    /// Why this is worth reporting: the declaration
    /// ([`Self::declared_macro_state`]) is installed once per scan, while a
    /// database describes one translation unit per entry. A source the build
    /// does not compile is still scanned (ADR-0010 Decision 1: a finding in any
    /// arm some configuration compiles is reported), but its conditional
    /// definitions are then resolved under a configuration that excludes it —
    /// so a name defined only in an arm that configuration rules out resolves
    /// to nothing at all. hostap scanned with a `defconfig`-derived database is
    /// the worked example in `docs/design/multi-configuration-scanning.md` §7.
    ///
    /// Headers are deliberately not counted: a compile database lists compiled
    /// TUs only, so *every* header is "uncovered" and reporting them would say
    /// nothing. A header's conditional definitions should follow the
    /// declaration — that is where the declaration earns its keep.
    pub fn uncovered_sources<'a>(&self, scanned: &'a [String]) -> Vec<&'a str> {
        if self.configured_sources.is_empty() {
            return Vec::new();
        }
        scanned
            .iter()
            .filter(|p| p.ends_with(".c"))
            .filter(|p| !self.configured_sources.contains(&real_path(Path::new(p))))
            .map(|p| p.as_str())
            .collect()
    }

    /// Merge the command-line macro state into `context`, filling only names
    /// the source-derived prescan did not already define.
    ///
    /// Call this *after* prescan and `#include` resolution so real definitions
    /// take precedence — see the "gap-filling, never overriding" invariant in
    /// the module docs. Returns the number of macro names newly contributed.
    ///
    /// `model` resolves a value written in terms of a limit (`-DCAP=INT_MAX`);
    /// only the names the database itself defines are merged, never the
    /// builtin constants the evaluation starts from.
    pub fn merge_defines_into(
        &self,
        context: &mut ProjectContext,
        model: crate::settings::IntFacts,
    ) -> Result<usize> {
        if self.defines.is_empty() {
            return Ok(0);
        }
        let source = self.define_directives();

        let mut parser = CParser::new()?;
        let (tree, source) = parser.parse_source(&source)?;
        let root = tree.root_node();

        let mut added = 0usize;

        for (name, value) in super::const_eval::collect_macro_constants(&root, &source, model) {
            if !self.defines.iter().any(|d| d.spelling == name) {
                continue;
            }
            if let std::collections::hash_map::Entry::Vacant(e) =
                Arc::make_mut(&mut context.macro_constants).entry(name)
            {
                e.insert(value);
                added += 1;
            }
        }
        for (name, target) in super::const_eval::collect_macro_aliases(&root, &source) {
            if let std::collections::hash_map::Entry::Vacant(e) =
                Arc::make_mut(&mut context.macro_aliases).entry(name)
            {
                e.insert(target);
                added += 1;
            }
        }
        for (name, m) in super::macro_expand::collect_function_macros(&root, &source) {
            if let std::collections::hash_map::Entry::Vacant(e) =
                Arc::make_mut(&mut context.function_macros).entry(name)
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
    /// cl's `/FI<header>`: included ahead of the first line of every TU.
    ForcedInclude(String),
}

/// Flags whose directory argument may be attached (`-Idir`) or separate
/// (`-I dir`). `-I` is by far the common one; the others appear in
/// hand-written and cross-compilation builds.
const DIR_FLAGS: &[&str] = &["-I", "-isystem", "-iquote", "-idirafter"];

/// cl.exe's header search directory options, in either spelling. `/imsvc` is
/// clang-cl's system-header form; `/external:I` is what cl (and CMake, for a
/// `SYSTEM` include directory) uses for third-party headers.
const MSVC_DIR_FLAGS: &[&str] = &["/I", "-I", "/imsvc", "-imsvc", "/external:I", "-external:I"];

/// Whether an entry was compiled by an MSVC-style driver, whose command line
/// is read with cl.exe's syntax (see the module docs).
pub(crate) fn is_msvc_driver(argv: &[String]) -> bool {
    if argv.iter().any(|a| a == "--driver-mode=cl") {
        return true;
    }
    // A compiler launcher (`CMAKE_C_COMPILER_LAUNCHER`) comes first and names
    // the real driver as its first argument: `sccache cl.exe /c ...`.
    let driver = argv
        .iter()
        .map(|a| executable_stem(a))
        .find(|stem| !COMPILER_LAUNCHERS.contains(&stem.as_str()));
    matches!(driver.as_deref(), Some("cl" | "clang-cl"))
}

/// Programs that run the compiler named by their first argument.
const COMPILER_LAUNCHERS: &[&str] = &["ccache", "sccache", "buildcache", "distcc", "icecc"];

/// An executable's file name, lowercased, without directories or `.exe`.
fn executable_stem(path: &str) -> String {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let base = base.to_ascii_lowercase();
    base.strip_suffix(".exe").unwrap_or(&base).to_string()
}

/// The flag in `flags` that `arg` starts with, preferring the longest so that
/// `-idirafter` is not shadowed by a shorter flag sharing its prefix.
fn longest_prefix<'a>(arg: &str, flags: &[&'a str]) -> Option<&'a str> {
    flags
        .iter()
        .copied()
        .filter(|f| arg.starts_with(f))
        .max_by_key(|f| f.len())
}

/// Extract the include/define/undefine flags from one tokenized command line.
/// `msvc` selects cl.exe's syntax in addition to the GCC spellings, which cl
/// also accepts; see the module docs for why it is not always on.
fn parse_flags(argv: &[String], msvc: bool) -> Vec<Flag> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        i += 1;

        if msvc {
            // Everything after /link is the linker's, and everything after
            // clang-cl's `--` is an input file: CMake writes `-- <SOURCE>`
            // precisely so a POSIX path is not read as `/U` or `/I`.
            if arg.eq_ignore_ascii_case("/link") || arg.eq_ignore_ascii_case("-link") || arg == "--"
            {
                break;
            }
            if let Some(rest) = arg.strip_prefix("/D") {
                if let Some(f) = define_flag(rest, argv, &mut i, true) {
                    out.push(f);
                }
                continue;
            }
            if let Some(rest) = arg.strip_prefix("/U") {
                if let Some(name) = take_value(rest, argv, &mut i) {
                    if !name.is_empty() {
                        out.push(Flag::Undefine(name));
                    }
                }
                continue;
            }
            if let Some(rest) = arg.strip_prefix("/FI").or_else(|| arg.strip_prefix("-FI")) {
                if let Some(header) = take_value(rest, argv, &mut i) {
                    if !header.is_empty() {
                        out.push(Flag::ForcedInclude(header));
                    }
                }
                continue;
            }
            if let Some(f) = longest_prefix(arg, MSVC_DIR_FLAGS) {
                if let Some(dir) = take_value(&arg[f.len()..], argv, &mut i) {
                    if !dir.is_empty() {
                        out.push(Flag::Include(dir));
                    }
                }
                continue;
            }
        }

        if let Some(rest) = arg.strip_prefix("-D") {
            if let Some(f) = define_flag(rest, argv, &mut i, msvc) {
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
        if let Some(f) = longest_prefix(arg, DIR_FLAGS) {
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
/// `-DNAME=VALUE` and the separate `-D NAME=VALUE` form. cl also accepts
/// `NAME#VALUE`, so under `msvc` a `#` separates as well.
fn define_flag(attached: &str, argv: &[String], i: &mut usize, msvc: bool) -> Option<Flag> {
    let text = take_value(attached, argv, i)?;
    if text.is_empty() {
        return None;
    }
    // Split on the first `=`, which for a function-like macro necessarily
    // follows the parameter list: `MAX(a,b)=...` has no `=` inside `(a,b)`
    // because a parameter list is only identifiers and commas.
    let sep = if msvc {
        text.find(['=', '#'])
    } else {
        text.find('=')
    };
    let (spelling, body) = match sep {
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
/// A path in the one spelling both sides of a comparison can agree on:
/// canonicalized when the file is really there, and the path as written when
/// it is not (a database from another host, or a unit test's fake tree).
/// The path as the filesystem resolves it, or as written when it does not
/// resolve. Two tables keyed on a path -- the database's compiled sources
/// here, the per-file summaries in `prescan` -- are both looked up with a
/// path the scan walk produced, which need not be spelled the way the walk
/// that filled them spelled it.
pub(crate) fn real_path(p: &Path) -> String {
    std::fs::canonicalize(p)
        .unwrap_or_else(|_| p.to_path_buf())
        .to_string_lossy()
        .to_string()
}

fn absolutize(base: &Path, dir: &str) -> PathBuf {
    let p = Path::new(dir);
    // A Windows absolute path is absolute on every host: joining `C:\inc` onto
    // the entry directory would only manufacture a path that exists nowhere,
    // where left alone it reaches `missing_include_paths` and gets reported.
    if p.is_absolute() || is_windows_absolute(dir) {
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
pub(crate) fn split_command(cmd: &str) -> Vec<String> {
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

/// `C:\x`, `C:/x` or a UNC `\\server\share` path.
fn is_windows_absolute(p: &str) -> bool {
    let b = p.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
        || p.starts_with("\\\\")
}

/// Split a `command` string with the quoting rules of the host that wrote it:
/// Windows rules when its driver (its first word, or the word after a compiler
/// launcher) is a Windows path or an `.exe`, POSIX rules otherwise.
pub(crate) fn split_command_for_host(cmd: &str) -> Vec<String> {
    let windows = split_command_windows(cmd);
    // Look past a compiler launcher to the driver it runs.
    let first = windows
        .iter()
        .find(|a| !COMPILER_LAUNCHERS.contains(&executable_stem(a).as_str()))
        .or(windows.first())
        .map(String::as_str)
        .unwrap_or("");
    if is_windows_absolute(first) || first.to_ascii_lowercase().ends_with(".exe") {
        windows
    } else {
        split_command(cmd)
    }
}

/// Split a command line the way the MSVC C runtime splits one into `argv`.
/// Backslashes are literal except before a `"`: `2n` of them there yield `n`
/// and the quote toggles quoting, `2n+1` yield `n` and a literal `"`. Inside
/// quotes, `""` is a literal `"` (the CRT's rule since 2008;
/// `CommandLineToArgvW` differs here). Arguments are separated by spaces and
/// tabs only, plus line breaks, which separate arguments in a response file.
pub(crate) fn split_command_windows(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut has_token = false;
    let mut in_quotes = false;
    let chars: Vec<char> = cmd.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' => {
                let start = i;
                while i < chars.len() && chars[i] == '\\' {
                    i += 1;
                }
                let n = i - start;
                has_token = true;
                if i < chars.len() && chars[i] == '"' {
                    cur.extend(std::iter::repeat_n('\\', n / 2));
                    if n % 2 == 1 {
                        cur.push('"');
                        i += 1;
                    }
                } else {
                    cur.extend(std::iter::repeat_n('\\', n));
                }
                continue;
            }
            '"' => {
                has_token = true;
                if in_quotes && chars.get(i + 1) == Some(&'"') {
                    cur.push('"');
                    i += 2;
                    continue;
                }
                in_quotes = !in_quotes;
            }
            ' ' | '\t' | '\r' | '\n' if !in_quotes => {
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
        i += 1;
    }
    if has_token {
        out.push(cur);
    }
    out
}

/// Nesting limit for `@file` response files, which may name further response
/// files.
const MAX_RESPONSE_FILE_DEPTH: usize = 8;

/// Replace each `@file` argument (after the driver) with the arguments the
/// file holds, resolved against the entry's directory. A response file that
/// cannot be read is dropped -- the same skip-don't-fail stance the loader
/// takes toward any entry it cannot understand -- and so is one already being
/// expanded further up, which would otherwise repeat until the depth limit.
pub(crate) fn expand_response_files(argv: Vec<String>, base: &Path, msvc: bool) -> Vec<String> {
    fn expand(
        args: Vec<String>,
        base: &Path,
        msvc: bool,
        open: &mut Vec<PathBuf>,
        out: &mut Vec<String>,
    ) {
        for arg in args {
            match arg.strip_prefix('@') {
                Some(file) if !file.is_empty() => {
                    if open.len() >= MAX_RESPONSE_FILE_DEPTH {
                        continue;
                    }
                    let path = absolutize(base, file);
                    let path = std::fs::canonicalize(&path).unwrap_or(path);
                    if open.contains(&path) {
                        continue;
                    }
                    let Some(text) = read_response_file(&path) else {
                        continue;
                    };
                    let inner = if msvc {
                        split_command_windows(&text)
                    } else {
                        split_command(&text)
                    };
                    open.push(path);
                    expand(inner, base, msvc, open, out);
                    open.pop();
                }
                _ => out.push(arg),
            }
        }
    }
    let mut out = Vec::with_capacity(argv.len());
    let mut args = argv.into_iter();
    if let Some(driver) = args.next() {
        out.push(driver);
    }
    expand(args.collect(), base, msvc, &mut Vec::new(), &mut out);
    out
}

/// Read a response file as text. cl's tools write them as UTF-16 as often as
/// UTF-8: a byte-order mark says which, and without one, NUL bytes in the
/// odd positions give away UTF-16LE (no command-line text contains a NUL).
fn read_response_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let utf16 = |data: &[u8], from: fn([u8; 2]) -> u16| {
        let units: Vec<u16> = data.chunks_exact(2).map(|c| from([c[0], c[1]])).collect();
        String::from_utf16(&units).ok()
    };
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return utf16(rest, u16::from_le_bytes);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return utf16(rest, u16::from_be_bytes);
    }
    if bytes.len() >= 2 && bytes.len() % 2 == 0 && bytes.iter().skip(1).step_by(2).all(|&b| b == 0)
    {
        return utf16(&bytes, u16::from_le_bytes);
    }
    let rest = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&bytes);
    String::from_utf8(rest.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_attached_and_separate_include_flags() {
        let flags = parse_flags(&argv(&["cc", "-Iinc", "-I", "other", "-c", "a.c"]), false);
        assert_eq!(
            flags,
            vec![Flag::Include("inc".into()), Flag::Include("other".into()),]
        );
    }

    #[test]
    fn parses_long_include_flag_forms() {
        let flags = parse_flags(
            &argv(&[
                "cc",
                "-isystem",
                "/usr/local/include",
                "-iquote=q",
                "-idirafter",
                "after",
            ]),
            false,
        );
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
        let flags = parse_flags(&argv(&["cc", "-DFOO", "-DBAR=2", "-D", "BAZ=3"]), false);
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
        let flags = parse_flags(&argv(&["cc", "-DMAX(a,b)=((a)>(b)?(a):(b))"]), false);
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
                file: None,
                command: Some("cc -DFOO=1 -DKEEP=2 -c a.c".into()),
                arguments: None,
            },
            RawEntry {
                directory: "/p".into(),
                file: None,
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
            file: None,
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
                file: None,
                command: Some("cc -Ia -Ib -c a.c".into()),
                arguments: None,
            },
            RawEntry {
                directory: "/p".into(),
                file: None,
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
            file: None,
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
                file: None,
                command: Some("/usr/bin/cc -c a.c".into()),
                arguments: None,
            },
            RawEntry {
                directory: "/p".into(),
                file: None,
                command: Some("/usr/bin/cc -c b.c".into()),
                arguments: None,
            },
            RawEntry {
                directory: "/p".into(),
                file: None,
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
                file: None,
                command: None,
                arguments: None,
            },
            RawEntry {
                directory: "/p".into(),
                file: None,
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
        Arc::make_mut(&mut ctx.macro_constants).insert("BUFSZ".into(), 64);

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
        db.merge_defines_into(&mut ctx, Default::default()).unwrap();

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
        db.merge_defines_into(&mut ctx, Default::default()).unwrap();
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
            &db.forced_includes,
            &db.include_paths,
            &[root.to_string_lossy().to_string()],
            &mut ctx,
            None,
            false,
            Default::default(),
            &super::super::include_names::HeaderLookup::default(),
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
    fn declared_macro_state_reports_defines_defined_and_undefines_undefined() {
        let entries = vec![
            RawEntry {
                directory: "/p".into(),
                file: None,
                command: Some("cc -DNDEBUG -DCONFIG_SAE=1 -DZERO=0 -UCONFIG_GAS -c a.c".into()),
                arguments: None,
            },
            // A second entry -U'ing a name the first -D'd: the filter already
            // drops it from `defines`, and the state must say *undefined*
            // rather than merely omitting it.
            RawEntry {
                directory: "/p".into(),
                file: None,
                command: Some("cc -UCONFIG_SAE -c b.c".into()),
                arguments: None,
            },
        ];
        let state = CompileDb::from_entries(&entries).declared_macro_state();
        assert_eq!(state.get("NDEBUG"), Some(&true), "bare -D is defined");
        assert_eq!(
            state.get("ZERO"),
            Some(&true),
            "-DZERO=0 is still *defined*: #ifdef tests definedness, not value"
        );
        assert_eq!(state.get("CONFIG_GAS"), Some(&false), "-U is undefined");
        assert_eq!(
            state.get("CONFIG_SAE"),
            Some(&false),
            "-U anywhere in the database wins over -D anywhere in it, in the \
             state table exactly as in `defines`"
        );
        assert!(
            !state.contains_key("WPA_TRACE"),
            "a name the build never mentions gets no opinion"
        );
    }

    #[test]
    fn uncovered_sources_names_scanned_c_files_the_build_does_not_compile() {
        let entries = vec![RawEntry {
            directory: "/p".into(),
            file: Some("built.c".into()),
            command: Some("cc -DFOO -c built.c".into()),
            arguments: None,
        }];
        let db = CompileDb::from_entries(&entries);
        let scanned = vec![
            "/p/built.c".to_string(),
            "/p/not_built.c".to_string(),
            // A header is never a database entry, so counting it would report
            // every header in the tree and mean nothing.
            "/p/header.h".to_string(),
        ];
        assert_eq!(db.uncovered_sources(&scanned), vec!["/p/not_built.c"]);
    }

    #[test]
    fn uncovered_sources_is_empty_when_the_database_names_no_files() {
        // `file` is optional in our reader; a database without it says nothing
        // about which sources the build compiles, so nothing is "uncovered".
        let entries = vec![RawEntry {
            directory: "/p".into(),
            file: None,
            command: Some("cc -DFOO -c a.c".into()),
            arguments: None,
        }];
        let db = CompileDb::from_entries(&entries);
        assert!(db
            .uncovered_sources(&["/p/a.c".to_string(), "/p/b.c".to_string()])
            .is_empty());
    }

    #[test]
    fn declared_macro_state_is_empty_for_a_database_with_no_macro_flags() {
        let entries = vec![RawEntry {
            directory: "/p".into(),
            file: None,
            command: Some("cc -I/inc -c a.c".into()),
            arguments: None,
        }];
        assert!(CompileDb::from_entries(&entries)
            .declared_macro_state()
            .is_empty());
    }

    #[test]
    fn merge_defines_is_a_noop_without_defines() {
        let mut ctx = ProjectContext::new();
        let db = CompileDb::default();
        assert_eq!(
            db.merge_defines_into(&mut ctx, Default::default()).unwrap(),
            0
        );
        assert!(ctx.macro_constants.is_empty());
    }

    // ---- MSVC command lines ------------------------------------------------

    fn entry(directory: &str, command: Option<&str>, arguments: Option<&[&str]>) -> RawEntry {
        RawEntry {
            directory: directory.into(),
            file: None,
            command: command.map(Into::into),
            arguments: arguments.map(argv),
        }
    }

    #[test]
    fn msvc_driver_is_recognised_by_name_path_case_and_driver_mode() {
        for driver in [
            "cl",
            "cl.exe",
            "CL.EXE",
            r"C:\PROGRA~1\MICROS~1\2022\BUILDT~1\VC\Tools\MSVC\1444~1.352\bin\Hostx64\x64\cl.exe",
            "/opt/msvc/bin/cl",
            "clang-cl",
            "clang-cl.exe",
        ] {
            assert!(is_msvc_driver(&argv(&[driver, "-c", "a.c"])), "{driver}");
        }
        assert!(is_msvc_driver(&argv(&[
            "clang",
            "--driver-mode=cl",
            "-c",
            "a.c"
        ])));
        for driver in [
            "cc",
            "gcc",
            "clang",
            "/usr/bin/cl-tool",
            "x86_64-w64-mingw32-gcc.exe",
        ] {
            assert!(!is_msvc_driver(&argv(&[driver, "-c", "a.c"])), "{driver}");
        }
    }

    #[test]
    fn msvc_define_forms_in_both_spellings() {
        let flags = parse_flags(
            &argv(&[
                "cl", "/DFOO", "/DBAR=2", "/D", "BAZ=3", "-DQUX", "/DHASH#4", "-D", "SEP#5",
            ]),
            true,
        );
        assert_eq!(
            flags,
            vec![
                Flag::Define("FOO".into(), String::new()),
                Flag::Define("BAR".into(), "2".into()),
                Flag::Define("BAZ".into(), "3".into()),
                Flag::Define("QUX".into(), String::new()),
                Flag::Define("HASH".into(), "4".into()),
                Flag::Define("SEP".into(), "5".into()),
            ]
        );
    }

    #[test]
    fn msvc_include_forms_in_both_spellings() {
        let flags = parse_flags(
            &argv(&[
                "cl",
                "/Iinc",
                "/I",
                r"C:\Program Files\sdk",
                "-Idash",
                "/imsvc",
                "sys",
                "/external:Iext",
                "-external:I",
                "ext2",
            ]),
            true,
        );
        assert_eq!(
            flags,
            vec![
                Flag::Include("inc".into()),
                Flag::Include(r"C:\Program Files\sdk".into()),
                Flag::Include("dash".into()),
                Flag::Include("sys".into()),
                Flag::Include("ext".into()),
                Flag::Include("ext2".into()),
            ]
        );
    }

    #[test]
    fn msvc_undefine_and_forced_include_forms() {
        let flags = parse_flags(
            &argv(&[
                "cl", "/UONE", "/U", "TWO", "-UTHREE", "/FIpch.h", "/FI", "b.h", "-FIc.h",
            ]),
            true,
        );
        assert_eq!(
            flags,
            vec![
                Flag::Undefine("ONE".into()),
                Flag::Undefine("TWO".into()),
                Flag::Undefine("THREE".into()),
                Flag::ForcedInclude("pch.h".into()),
                Flag::ForcedInclude("b.h".into()),
                Flag::ForcedInclude("c.h".into()),
            ]
        );
    }

    #[test]
    fn unknown_cl_flags_are_ignored_and_lookalikes_are_not_misread() {
        // `/Fi` (preprocessed-output name) is not `/FI`; `/external:W0` is not
        // `/external:I`; none of these is an error.
        let flags = parse_flags(
            &argv(&[
                "cl",
                "/nologo",
                "/TC",
                "/W3",
                "/O2",
                "/MT",
                "/Zi",
                "/FoCMakeFiles\\a.obj",
                "/Fiout.i",
                "/FdTARGET_COMPILE_PDB",
                "/FS",
                "/external:W0",
                "/external:anglebrackets",
                "/diagnostics:column",
                "/utf-8",
                "-c",
                "a.c",
            ]),
            true,
        );
        assert!(flags.is_empty(), "{flags:?}");
    }

    #[test]
    fn slash_flags_are_not_read_for_a_gcc_style_driver() {
        // POSIX absolute paths that would read as /U, /I, /D and /FI.
        let flags = parse_flags(
            &argv(&[
                "cc",
                "/Users/me/a.c",
                "/Include/x.c",
                "/Data/y.c",
                "/FIles/z.c",
                "-DKEEP",
            ]),
            false,
        );
        assert_eq!(flags, vec![Flag::Define("KEEP".into(), String::new())]);
    }

    #[test]
    fn hash_is_part_of_the_value_for_a_gcc_style_driver() {
        let flags = parse_flags(&argv(&["cc", "-DA#B=1"]), false);
        assert_eq!(flags, vec![Flag::Define("A#B".into(), "1".into())]);
    }

    #[test]
    fn msvc_parsing_stops_at_link() {
        let flags = parse_flags(
            &argv(&[
                "cl",
                "/DA",
                "a.c",
                "/link",
                "/DEBUG",
                "/INCREMENTAL:NO",
                "/DB",
            ]),
            true,
        );
        assert_eq!(flags, vec![Flag::Define("A".into(), String::new())]);
    }

    #[test]
    fn split_command_windows_follows_crt_backslash_and_quote_rules() {
        assert_eq!(
            split_command_windows(
                r#"cl.exe C:\a\b.c "C:\Program Files\inc" /DS=\"hi\" "tail\\" x"#
            ),
            argv(&[
                "cl.exe",
                r"C:\a\b.c",
                r"C:\Program Files\inc",
                r#"/DS="hi""#,
                r"tail\",
                "x",
            ])
        );
        // Inside quotes, "" is a literal quote.
        assert_eq!(
            split_command_windows(r#"cl "say ""x""" y"#),
            argv(&["cl", r#"say "x""#, "y"])
        );
        // An odd run of backslashes before a quote keeps the quote literal.
        assert_eq!(split_command_windows(r#"a\\\"b"#), argv(&[r#"a\"b"#]));
    }

    #[test]
    fn command_string_quoting_follows_the_host_that_wrote_it() {
        assert_eq!(
            split_command_for_host(r"C:\VS\cl.exe /IC:\src\inc -c a.c"),
            argv(&[r"C:\VS\cl.exe", r"/IC:\src\inc", "-c", "a.c"])
        );
        assert_eq!(
            split_command_for_host(r#"cc -DS=\"hi\" -c a.c"#),
            argv(&["cc", r#"-DS="hi""#, "-c", "a.c"])
        );
    }

    /// The shape CMake's Ninja generator writes for cl: a short-name driver
    /// path, `-D` for target definitions and `/D` for the configuration's own,
    /// Windows paths throughout.
    #[test]
    fn cmake_style_cl_command_is_read_with_msvc_syntax() {
        let cmd = r#"C:\PROGRA~2\MICROS~2\2022\BUILDT~1\VC\Tools\MSVC\1444~1.352\bin\Hostx64\x86\cl.exe  /nologo -DVTARCH_X86 -DVTBIT=32 -DUNICODE -I"C:\src\Ventoy2Disk" -external:I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um" /DWIN32 /D_WINDOWS /O2 /Ob2 /DNDEBUG -MT /FIforced.h /FoCMakeFiles\v.dir\a.c.obj /FdTARGET_COMPILE_PDB /FS -c C:\src\Ventoy2Disk\a.c"#;
        let db = CompileDb::from_entries(&[entry(r"C:\build", Some(cmd), None)]);
        let names: Vec<&str> = db.defines.iter().map(|d| d.name()).collect();
        assert_eq!(
            names,
            vec![
                "VTARCH_X86",
                "VTBIT",
                "UNICODE",
                "WIN32",
                "_WINDOWS",
                "NDEBUG"
            ]
        );
        // Windows-absolute paths are left alone, not joined onto the
        // entry's directory.
        assert_eq!(
            db.include_paths,
            vec![
                r"C:\src\Ventoy2Disk",
                r"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um",
            ]
        );
        assert_eq!(db.forced_includes, vec!["forced.h"]);
        assert!(db.compilers[0].ends_with(r"\cl.exe"));
    }

    #[test]
    fn gcc_style_entry_is_unaffected_by_msvc_support() {
        let db = CompileDb::from_entries(&[entry(
            "/p",
            Some("cc -DA=1 -Iinc /Users/x/b.c -c a.c"),
            None,
        )]);
        assert_eq!(
            db.defines,
            vec![CommandLineDefine {
                spelling: "A".into(),
                body: "1".into()
            }]
        );
        assert_eq!(db.include_paths, vec!["/p/inc"]);
        assert!(db.forced_includes.is_empty());
    }

    #[test]
    fn response_files_expand_in_place_utf8_and_utf16() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rsp"), "/DFROM_UTF8 /I inc\r\n").unwrap();
        let mut u16 = vec![0xFF, 0xFE];
        for unit in "/DFROM_UTF16 \"/Iwide dir\"".encode_utf16() {
            u16.extend(unit.to_le_bytes());
        }
        std::fs::write(dir.path().join("w.rsp"), u16).unwrap();
        std::fs::write(dir.path().join("loop.rsp"), "@loop.rsp /DAFTER_LOOP").unwrap();

        let d = dir.path().to_string_lossy().to_string();
        let db = CompileDb::from_entries(&[entry(
            &d,
            None,
            Some(&[
                "cl.exe",
                "@a.rsp",
                "@w.rsp",
                "@missing.rsp",
                "@loop.rsp",
                "/DLAST",
                "-c",
                "x.c",
            ]),
        )]);
        let names: Vec<&str> = db.defines.iter().map(|d| d.name()).collect();
        assert_eq!(names, vec!["FROM_UTF8", "FROM_UTF16", "AFTER_LOOP", "LAST"]);
        assert_eq!(
            db.include_paths,
            vec![format!("{d}/inc"), format!("{d}/wide dir")]
        );
    }

    #[test]
    fn forced_include_is_absolutized_when_it_exists_beside_the_entry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("here.h"), "").unwrap();
        let d = dir.path().to_string_lossy().to_string();
        let db = CompileDb::from_entries(&[entry(
            &d,
            None,
            Some(&[
                "cl",
                "/FIhere.h",
                "/FIelsewhere.h",
                "/FIhere.h",
                "-c",
                "a.c",
            ]),
        )]);
        assert_eq!(
            db.forced_includes,
            vec![format!("{d}/here.h"), "elsewhere.h".to_string()]
        );
    }

    /// A header reached *only* through `/FI` -- no source file includes it --
    /// contributes its macros, the way cl makes them visible to every TU.
    #[test]
    fn forced_include_brings_header_macros_into_context() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("inc")).unwrap();
        std::fs::write(root.join("inc/forced.h"), "#define FORCED_LEN 12\n").unwrap();
        let c_file = root.join("a.c");
        std::fs::write(&c_file, "int f(void) { return 0; }\n").unwrap();

        let db = CompileDb::from_entries(&[entry(
            &root.to_string_lossy(),
            None,
            Some(&["cl.exe", "/I", "inc", "/FI", "forced.h", "-c", "a.c"]),
        )]);
        assert_eq!(db.forced_includes, vec!["forced.h"]);

        let mut ctx = ProjectContext::new();
        super::super::prescan::resolve_includes(
            &[c_file.to_string_lossy().to_string()],
            &db.forced_includes,
            &db.include_paths,
            &[root.to_string_lossy().to_string()],
            &mut ctx,
            None,
            false,
            Default::default(),
            &super::super::include_names::HeaderLookup::default(),
        )
        .unwrap();
        assert_eq!(ctx.macro_constants.get("FORCED_LEN"), Some(&12));
    }

    #[test]
    fn windows_absolute_paths_are_recognised_on_any_host() {
        assert!(is_windows_absolute(r"C:\x"));
        assert!(is_windows_absolute("d:/x"));
        assert!(is_windows_absolute(r"\\wsl.localhost\Ubuntu\home"));
        assert!(!is_windows_absolute("C:x"));
        assert!(!is_windows_absolute("inc"));
        assert!(!is_windows_absolute("/usr/include"));
    }

    // ---- review follow-ups ------------------------------------------------

    fn resolve_with(db: &CompileDb, root: &Path, sources: &[&Path]) -> ProjectContext {
        let mut ctx = ProjectContext::new();
        let sources: Vec<String> = sources
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        super::super::prescan::resolve_includes(
            &sources,
            &db.forced_includes,
            &db.include_paths,
            &[root.to_string_lossy().to_string()],
            &mut ctx,
            None,
            false,
            Default::default(),
            &super::super::include_names::HeaderLookup::default(),
        )
        .unwrap();
        ctx
    }

    /// `cl /FIcfg.h` with the header beside the build and no `/I` at all: the
    /// forced include is absolute, and must still be opened.
    #[test]
    fn forced_include_beside_the_entry_resolves_with_no_search_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("cfg.h"), "#define IDX 8\n").unwrap();
        let c_file = root.join("a.c");
        std::fs::write(&c_file, "static int t[8];\n").unwrap();
        let db = CompileDb::from_entries(&[entry(
            &root.to_string_lossy(),
            Some("cl /FIcfg.h -c a.c"),
            None,
        )]);
        assert!(db.include_paths.is_empty());
        let ctx = resolve_with(&db, root, &[&c_file]);
        assert_eq!(ctx.macro_constants.get("IDX"), Some(&8));
    }

    /// Forced includes come first and in command-line order, the way cl
    /// reads them; a header a source includes comes after them, so a later
    /// definition of the same constant is the one kept, as in the TU's text.
    #[test]
    fn forced_includes_resolve_first_and_in_command_line_order() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("one.h"), "#define ORDER 1\n").unwrap();
        std::fs::write(root.join("two.h"), "#define ORDER 2\n").unwrap();
        std::fs::write(root.join("three.h"), "#define ORDER 3\n").unwrap();
        let plain = root.join("plain.c");
        std::fs::write(&plain, "int x;\n").unwrap();
        let includes = root.join("includes.c");
        std::fs::write(&includes, "#include \"three.h\"\nint y;\n").unwrap();
        let db = CompileDb::from_entries(&[entry(
            &root.to_string_lossy(),
            Some("cl /FIone.h /FItwo.h -c plain.c"),
            None,
        )]);

        let ctx = resolve_with(&db, root, &[&plain]);
        assert_eq!(
            ctx.macro_constants.get("ORDER"),
            Some(&2),
            "two.h follows one.h"
        );

        let ctx = resolve_with(&db, root, &[&includes]);
        assert_eq!(
            ctx.macro_constants.get("ORDER"),
            Some(&3),
            "a source's own #include follows every forced include"
        );
    }

    #[test]
    fn msvc_parsing_stops_at_double_dash() {
        // CMake writes `-- <SOURCE>` for clang-cl so a POSIX source path is
        // not read as /I or /D.
        let flags = parse_flags(
            &argv(&["clang-cl", "/DX", "-c", "--", "/Include/a.c", "/Data/b.c"]),
            true,
        );
        assert_eq!(flags, vec![Flag::Define("X".into(), String::new())]);
    }

    #[test]
    fn msvc_driver_is_found_behind_a_compiler_launcher() {
        assert!(is_msvc_driver(&argv(&["sccache", "cl.exe", "/c", "a.c"])));
        assert!(is_msvc_driver(&argv(&[
            r"C:\tools\sccache.exe",
            r"C:\VS\cl.exe",
            "/c",
            "a.c"
        ])));
        assert!(is_msvc_driver(&argv(&["ccache", "clang-cl", "/c", "a.c"])));
        assert!(!is_msvc_driver(&argv(&["ccache", "gcc", "-c", "a.c"])));
        assert!(!is_msvc_driver(&argv(&["ccache"])));
        assert_eq!(
            split_command_for_host(r"sccache C:\VS\cl.exe /IC:\src\inc -c a.c"),
            argv(&["sccache", r"C:\VS\cl.exe", r"/IC:\src\inc", "-c", "a.c"])
        );
        let db = CompileDb::from_entries(&[entry(
            "/p",
            Some(r"sccache C:\VS\cl.exe /DFROM_CL /IC:\src\inc -c a.c"),
            None,
        )]);
        assert_eq!(db.defines[0].name(), "FROM_CL");
        assert_eq!(db.include_paths, vec![r"C:\src\inc"]);
    }

    #[test]
    fn driver_mode_in_a_response_file_selects_msvc_syntax() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("opts.rsp"),
            r"--driver-mode=cl /DFROM_RSP /IC:\sdk\um",
        )
        .unwrap();
        let db = CompileDb::from_entries(&[entry(
            &dir.path().to_string_lossy(),
            None,
            Some(&["clang", "@opts.rsp", "-c", "a.c"]),
        )]);
        assert_eq!(db.defines[0].name(), "FROM_RSP");
        // Re-read with cl's quoting, so the backslashes survive.
        assert_eq!(db.include_paths, vec![r"C:\sdk\um"]);
    }

    #[test]
    fn response_file_cycles_are_cut_not_repeated() {
        let dir = tempfile::tempdir().unwrap();
        // Ten self-references would be 10^8 reads if only depth bounded it.
        std::fs::write(
            dir.path().join("self.rsp"),
            format!("{} /DSELF", "@self.rsp ".repeat(10)),
        )
        .unwrap();
        std::fs::write(dir.path().join("a.rsp"), "/DA @b.rsp").unwrap();
        std::fs::write(dir.path().join("b.rsp"), "/DB @a.rsp").unwrap();
        let started = std::time::Instant::now();
        let expanded = expand_response_files(
            argv(&["cl", "@self.rsp", "@a.rsp", "@self.rsp"]),
            dir.path(),
            true,
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(expanded, argv(&["cl", "/DSELF", "/DA", "/DB", "/DSELF"]));
    }

    #[test]
    fn utf16_response_files_decode_without_a_bom_and_big_endian() {
        let dir = tempfile::tempdir().unwrap();
        let le: Vec<u8> = "/DLE_NO_BOM"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        std::fs::write(dir.path().join("le.rsp"), le).unwrap();
        let mut be = vec![0xFE, 0xFF];
        be.extend("/DBE_BOM".encode_utf16().flat_map(u16::to_be_bytes));
        std::fs::write(dir.path().join("be.rsp"), be).unwrap();
        let expanded = expand_response_files(argv(&["cl", "@le.rsp", "@be.rsp"]), dir.path(), true);
        assert_eq!(expanded, argv(&["cl", "/DLE_NO_BOM", "/DBE_BOM"]));
    }

    #[test]
    fn split_command_windows_separates_on_crt_whitespace_only() {
        // A no-break space or a vertical tab is part of an argument to the
        // CRT; spaces, tabs and response-file line breaks separate.
        assert_eq!(
            split_command_windows("cl /DA\u{a0}B\t/DC\u{b}D\r\n/DE"),
            argv(&["cl", "/DA\u{a0}B", "/DC\u{b}D", "/DE"])
        );
    }
}
