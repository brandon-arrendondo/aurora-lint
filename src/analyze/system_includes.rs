//! Recovering a compiler's *implicit* system header directories (task 623).
//!
//! # Why a compile database is not enough
//!
//! [`super::compile_commands`] reads the flags a build **passes**. A build
//! never passes its compiler's own built-in search directories, because the
//! compiler already knows them — so `/usr/include`, the Debian multiarch
//! directory, and the gcc internal include directory are absent from every
//! `compile_commands.json` by construction. Asking the compiler is the only
//! way to learn them:
//!
//! ```text
//! $ echo | cc -E -Wp,-v -x c -
//! #include "..." search starts here:
//! #include <...> search starts here:
//!  /usr/lib/gcc/x86_64-linux-gnu/12/include
//!  /usr/local/include
//!  /usr/include/x86_64-linux-gnu
//!  /usr/include
//! End of search list.
//! ```
//!
//! What this actually buys, measured on the benchmark host: `<sys/queue.h>`
//! (the motivating example in `docs/design/macro-expansion.md` §5(D)) already
//! lives in `/usr/include`, which several project configs hand-feed via `-I`
//! anyway. The directories nothing reaches today are the other two — the
//! multiarch directory, where glibc's `bits/*.h` live, so a `<bits/...>`
//! include from an otherwise-reachable header dead-ends; and the gcc internal
//! directory, which is where `stdarg.h`, `stddef.h` and `stdbool.h` *actually*
//! live, since glibc does not ship them. Without it `NULL`, `offsetof`,
//! `va_list` and `bool`/`true`/`false` are never harvested from their real
//! definitions.
//!
//! # Why this is opt-in, and separate from `--compile-commands`
//!
//! Two reasons, and both are about keeping effects attributable:
//!
//! - It **spawns a subprocess**, which is the one thing Phase 4 was scoped to
//!   avoid (`docs/design/macro-expansion.md` §11). Nothing here runs unless the
//!   user asks for it.
//! - The compile-database half was measured on its own first, and came out at
//!   −0.09% of findings. Keeping this behind its own flag means a later
//!   measurement can attribute any change to *this* and not to the database.
//!
//! # Known sharp edge
//!
//! [`super::prescan::resolve_includes`] harvests header macros with
//! `macro_constants.extend(...)` — **override** semantics, unlike the
//! carefully gap-filling `or_insert` that `-D` flags get. Pointing the resolver
//! at the system header tree therefore lets a libc macro win over a project
//! macro of the same name. That is pre-existing behavior for any `-I` path, but
//! this flag is the first thing to aim it at all of `/usr/include`. Measure
//! before trusting a delta from it.

use std::collections::HashSet;
use std::path::Path;
use std::process::{Command, Stdio};

/// The compiler to ask when nothing else names one.
///
/// `cc` rather than `gcc` or `clang`: it is the platform's configured default C
/// compiler, which is the one whose search list a build without a compile
/// database most likely used.
pub const DEFAULT_COMPILER: &str = "cc";

/// Outcome of querying one or more compilers for their built-in search list.
///
/// Failures are carried rather than raised: a compile database routinely names
/// a cross-compiler that is not installed on the machine doing the analysis,
/// and losing one compiler's directories is not a reason to fail a scan.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SystemIncludes {
    /// Existing directories, first-seen order preserved so the compiler's own
    /// search order is approximated, deduplicated across compilers.
    pub paths: Vec<String>,
    /// Compilers that answered, in the order asked.
    pub queried: Vec<String>,
    /// Compilers that could not be asked, with the reason, for the caller to
    /// surface. A silent miss here would look exactly like a compiler with no
    /// system directories.
    pub failed: Vec<(String, String)>,
}

/// Ask each compiler for its built-in include directories.
///
/// `compilers` is deduplicated before anything is spawned, so each distinct
/// compiler is asked exactly once per call — the CLI calls this once per run,
/// so that is the whole of the caching the query needs.
pub fn query(compilers: &[String]) -> SystemIncludes {
    let mut out = SystemIncludes::default();
    let mut seen_paths: HashSet<String> = HashSet::new();
    let mut asked: HashSet<&str> = HashSet::new();

    for compiler in compilers {
        if !asked.insert(compiler.as_str()) {
            continue;
        }
        match run_query(compiler) {
            Ok(stderr) => {
                out.queried.push(compiler.clone());
                for dir in parse_search_list(&stderr) {
                    // A compiler lists directories that need not exist (gcc
                    // prints "ignoring nonexistent directory" for those, but
                    // sysroot-relative spellings can slip through). Feeding a
                    // nonexistent path to resolve_includes is harmless but
                    // pointless, and it would make the reported count a lie.
                    if Path::new(&dir).is_dir() && seen_paths.insert(dir.clone()) {
                        out.paths.push(dir);
                    }
                }
            }
            Err(e) => out.failed.push((compiler.clone(), e)),
        }
    }
    out
}

/// Run `<compiler> -E -Wp,-v -x c -` on empty input and return its stderr.
///
/// `-x c` forces the C frontend regardless of how the driver would classify
/// `-`, and stdin is `/dev/null` so the preprocessor sees EOF immediately
/// rather than waiting for input it will never get — the difference between a
/// query and a hang.
fn run_query(compiler: &str) -> Result<String, String> {
    let output = Command::new(compiler)
        .args(["-E", "-Wp,-v", "-x", "c", "-"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| e.to_string())?;

    // The search list goes to stderr, and a compiler that printed one has done
    // its job even if it then exited nonzero for an unrelated reason. Only
    // treat this as a failure when there is nothing usable at all.
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() && !stderr.contains(SEARCH_LIST_START) {
        return Err(format!(
            "exited with {} and printed no search list",
            output
                .status
                .code()
                .map_or_else(|| "a signal".to_string(), |c| format!("status {c}"))
        ));
    }
    Ok(stderr)
}

/// Marker that opens the angle-bracket search list.
const SEARCH_LIST_START: &str = "#include <...> search starts here:";
/// Marker that opens the quoted-include search list, which precedes it.
const QUOTE_LIST_START: &str = "#include \"...\" search starts here:";
/// Marker that closes both.
const SEARCH_LIST_END: &str = "End of search list.";

/// Extract the include directories from a `-Wp,-v` stderr dump.
///
/// Both sections are collected: the quoted-include list comes first and is
/// normally a prefix of the angle-bracket one, but a compiler configured with
/// `-iquote` directories can list something there that appears nowhere else,
/// and a directory reachable either way is deduplicated by the caller.
///
/// Everything outside the markers is ignored, which is what discards gcc's
/// "ignoring nonexistent directory" preamble and clang's target banner.
fn parse_search_list(stderr: &str) -> Vec<String> {
    let mut dirs = Vec::new();
    let mut in_list = false;
    for line in stderr.lines() {
        let trimmed = line.trim();
        if trimmed == QUOTE_LIST_START || trimmed == SEARCH_LIST_START {
            in_list = true;
            continue;
        }
        if trimmed == SEARCH_LIST_END {
            in_list = false;
            continue;
        }
        if !in_list || trimmed.is_empty() {
            continue;
        }
        // A directory line is indented; anything flush-left inside the markers
        // is some other diagnostic and not a path.
        if line == trimmed {
            continue;
        }
        // Apple's driver annotates framework directories, which are not
        // header search paths in the sense resolve_includes understands.
        let dir = match trimmed.strip_suffix("(framework directory)") {
            Some(_) => continue,
            None => trimmed,
        };
        dirs.push(dir.to_string());
    }
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;

    const GCC_STDERR: &str = r#"Using built-in specs.
ignoring nonexistent directory "/usr/local/include/x86_64-linux-gnu"
ignoring nonexistent directory "/usr/lib/gcc/x86_64-linux-gnu/12/include-fixed"
#include "..." search starts here:
#include <...> search starts here:
 /usr/lib/gcc/x86_64-linux-gnu/12/include
 /usr/local/include
 /usr/include/x86_64-linux-gnu
 /usr/include
End of search list.
"#;

    #[test]
    fn parses_gcc_search_list() {
        assert_eq!(
            parse_search_list(GCC_STDERR),
            vec![
                "/usr/lib/gcc/x86_64-linux-gnu/12/include",
                "/usr/local/include",
                "/usr/include/x86_64-linux-gnu",
                "/usr/include",
            ]
        );
    }

    #[test]
    fn ignores_nonexistent_directory_preamble() {
        // The "ignoring nonexistent directory" lines sit before the markers and
        // name directories that must NOT be treated as search paths.
        let dirs = parse_search_list(GCC_STDERR);
        assert!(!dirs.iter().any(|d| d.contains("include-fixed")));
        assert!(!dirs.iter().any(|d| d.contains("local/include/x86_64")));
    }

    #[test]
    fn collects_both_quoted_and_angle_sections() {
        let stderr = "#include \"...\" search starts here:\n \
                      /project/quoted\n\
                      #include <...> search starts here:\n \
                      /usr/include\n\
                      End of search list.\n";
        assert_eq!(
            parse_search_list(stderr),
            vec!["/project/quoted", "/usr/include"]
        );
    }

    #[test]
    fn ignores_everything_outside_the_markers() {
        let stderr = "clang version 14.0.6\nTarget: x86_64-pc-linux-gnu\n\
                      /some/path/that/is/not/in/a/list\n";
        assert!(parse_search_list(stderr).is_empty());
    }

    #[test]
    fn skips_framework_directories() {
        let stderr = "#include <...> search starts here:\n \
                      /usr/include\n \
                      /System/Library/Frameworks (framework directory)\n\
                      End of search list.\n";
        assert_eq!(parse_search_list(stderr), vec!["/usr/include"]);
    }

    #[test]
    fn unindented_line_inside_the_markers_is_not_a_path() {
        let stderr = "#include <...> search starts here:\n\
                      some diagnostic flush left\n \
                      /usr/include\n\
                      End of search list.\n";
        assert_eq!(parse_search_list(stderr), vec!["/usr/include"]);
    }

    #[test]
    fn a_missing_compiler_is_reported_not_fatal() {
        let res = query(&["definitely-not-a-real-compiler-xyz".to_string()]);
        assert!(res.paths.is_empty());
        assert!(res.queried.is_empty());
        assert_eq!(res.failed.len(), 1);
        assert_eq!(res.failed[0].0, "definitely-not-a-real-compiler-xyz");
    }

    #[test]
    fn each_distinct_compiler_is_asked_once() {
        // Duplicates collapse: the dedup is what keeps a compile database
        // naming the same cc 500 times from spawning it 500 times.
        let res = query(&[
            "definitely-not-a-real-compiler-xyz".to_string(),
            "definitely-not-a-real-compiler-xyz".to_string(),
        ]);
        assert_eq!(res.failed.len(), 1);
    }

    #[test]
    fn returned_paths_exist_and_are_deduplicated() {
        // Uses the host's real cc. Skipped rather than failed where there is
        // none, so the suite stays green on a machine without a C compiler.
        let res = query(&[DEFAULT_COMPILER.to_string()]);
        if res.queried.is_empty() {
            return;
        }
        assert!(
            !res.paths.is_empty(),
            "a working cc should report at least one existing system include dir"
        );
        for p in &res.paths {
            assert!(Path::new(p).is_dir(), "{p} should exist");
        }
        let unique: HashSet<&String> = res.paths.iter().collect();
        assert_eq!(
            unique.len(),
            res.paths.len(),
            "paths should be deduplicated"
        );
    }
}
