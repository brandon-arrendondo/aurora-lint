//! Robustness: malformed and non-compiling C must scan to a clean exit.
//!
//! aurora-lint analyses code that does not have to compile. A missing quote
//! or `*/` moves string and comment text, UTF-8 included, into positions
//! where the parser recovers it as an `ERROR` node or an identifier, and code
//! that slices source text by byte offset, or assumes a `)` follows its `(`,
//! meets input no valid C produces. Graceful-failure containment (ADR-0017)
//! keeps such a crash from ending the scan; this suite is what keeps the
//! crashes from being written in the first place.
//!
//! Every case is scanned by the real binary with every rule enabled
//! (`rules_templates/rules-all.toml`), and must end with exit 0 or 1 and no
//! line marking the scan incomplete -- a crash, a step or time limit, an
//! analysis cap, the watchdog's hang, or any cause not yet known here
//! ([`classify`] is an allowlist). A file refused by the input guard (not
//! source text) is allowed only for the cases built to be refused, and exit 3
//! only when such a refusal is all that is incomplete.
//!
//! The cases come from two generators, not from a list of hand-picked files:
//!
//! - [`table_cases`]: a fixed table of malformations (unterminated literals
//!   and comments, unbalanced brackets, truncation mid-token and mid-UTF-8,
//!   BOM, CRLF, lone CR, NUL, invalid UTF-8, very long lines, binary blobs
//!   named `.c`) applied to a few base files, and stray UTF-8 spliced into
//!   identifier, operator, macro-argument, directive, string and comment
//!   positions.
//! - [`mutant_cases`]: seeded mutations of the rules' own `.c` fixtures --
//!   delete a quote or a `*/`, delete a bracket, splice UTF-8 at a character
//!   offset, cut at a byte offset that may split a UTF-8 sequence.
//!
//! Both are deterministic. `AURORA_LINT_ROBUSTNESS_SEED` and
//! `AURORA_LINT_ROBUSTNESS_MUTANTS` choose the seed and how many mutants a
//! run builds, so a longer run is the same test with a larger number; a
//! failure prints both, and keeps every failing input under
//! `robustness-failures/` in the target directory (`CARGO_TARGET_DIR` when
//! set) with the recipe that built it. `AURORA_LINT_ROBUSTNESS_WALL_SECS`
//! overrides how long one scan may run before the test calls it a hang.
//!
//! The suite raises confidence and catches regressions. It cannot show that
//! no input crashes or hangs the scan, and nothing should claim it does.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

/// The runner, as the tests share it. `cargo test` runs them on parallel
/// threads, and the scans the heavy ones start keep every core busy; a scan
/// timed beside them is slowed by however much of the runner they hold at
/// that moment, which on a few-core CI runner turned a size series that
/// measures 8x alone into 15x, and a 50 s scan into one past its 180 s
/// budget. A test that times a scan holds the runner alone ([`timed`]);
/// every other test that scans shares it ([`untimed`]), so the heavy scans
/// still run beside one another but never beside a timed one.
static RUNNER: RwLock<()> = RwLock::new(());

/// Hold the runner alone, for a test whose verdict is a time.
fn timed() -> RwLockWriteGuard<'static, ()> {
    RUNNER.write().unwrap_or_else(PoisonError::into_inner)
}

/// Share the runner with the other untimed tests.
fn untimed() -> RwLockReadGuard<'static, ()> {
    RUNNER.read().unwrap_or_else(PoisonError::into_inner)
}

/// The binary under test: this build's, or `AURORA_LINT_ROBUSTNESS_BIN` --
/// on WSL, a Windows build (`aurora-lint.exe`) run on cases written under
/// `/mnt/c` through `TMPDIR`, which covers Windows paths and a
/// case-insensitive file system.
fn aurora_lint_bin() -> PathBuf {
    std::env::var_os("AURORA_LINT_ROBUSTNESS_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_aurora-lint")))
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every rule, enabled.
fn all_rules_manifest() -> PathBuf {
    repo().join("rules_templates/rules-all.toml")
}

/// The default seed. Any value works; this one only has to stay fixed so a
/// plain `cargo test` is reproducible.
const DEFAULT_SEED: u64 = 0x5eed_c0de;

/// How many mutants a plain `cargo test` builds.
const DEFAULT_MUTANTS: usize = 120;

/// How long one scan may take, wall clock, before the test calls it a hang,
/// unless `AURORA_LINT_ROBUSTNESS_WALL_SECS` says otherwise. Far above what
/// the table and the mutants take; the scan's own `--rule-time-limit` fires
/// first for a single runaway rule.
const SCAN_WALL_LIMIT: Duration = Duration::from_secs(900);

/// The wall limit for the scan of every rule fixture, which in a debug
/// build on a loaded machine has come within a minute of
/// [`SCAN_WALL_LIMIT`] and grows with every fixture added.
const FIXTURES_WALL_LIMIT: Duration = Duration::from_secs(3600);

/// `default`, or `AURORA_LINT_ROBUSTNESS_WALL_SECS` when it is set.
fn wall_limit(default: Duration) -> Duration {
    std::env::var("AURORA_LINT_ROBUSTNESS_WALL_SECS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .map_or(default, Duration::from_secs)
}

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

// -- deterministic randomness ------------------------------------------------

/// SplitMix64: small, seedable and the same on every platform, which is all
/// a reproducible mutation needs.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n`; `n` must be non-zero.
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

// -- cases -------------------------------------------------------------------

/// What the input guard is expected to do with a case.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Refuse {
    /// Source text: refusing it is a failure.
    Never,
    /// Not source text (a binary blob named `.c`): it must be refused.
    Must,
    /// Either refused (too large) or analysed within budget.
    May,
}

/// One input to scan.
struct Case {
    /// The file name it is written under; also how a failure names it.
    name: String,
    bytes: Vec<u8>,
    /// How it was built, for a failure report.
    recipe: String,
    /// Whether the input guard may, or must, refuse it.
    refuse: Refuse,
}

impl Case {
    fn new(name: impl Into<String>, bytes: impl Into<Vec<u8>>, recipe: impl Into<String>) -> Self {
        Case {
            name: name.into(),
            bytes: bytes.into(),
            recipe: recipe.into(),
            refuse: Refuse::Never,
        }
    }
}

/// Valid C that touches most of what the rules look at: includes, a
/// function-like macro and `#` stringizing, a struct with an array and a
/// bit-field, a loop over a subscript, a switch, a call with a format string,
/// a block and a line comment, a character literal.
const BASE_FUNCTION: &str = r#"#include <stdio.h>
#include <string.h>
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define STR(x) #x
struct rec { int count; char name[16]; unsigned flag : 3; };
static int total = 0;
int copy_name(struct rec *r, const char *src, size_t n) {
    char local[32];
    int i;
    if (src == NULL) { return -1; }
    for (i = 0; i < (int)n && src[i] != '\0'; i++) {
        local[i % 32] = src[i];
    }
    switch (n) { case 1: total++; break; default: break; }
    printf("%s %d\n", "copied", MAX(i, 3));
    /* the name is bounded by its array */
    strncpy(r->name, local, sizeof r->name - 1);
    return strlen(local) > 3 ? 1 : 0; // trailing comment
}
"#;

/// A header: guards, a conditional block, prototypes, a typedef'd function
/// pointer and an enum.
const BASE_HEADER: &str = r#"#ifndef REC_H
#define REC_H
#if defined(_WIN32) && !defined(REC_STATIC)
#  define REC_API __declspec(dllexport)
#else
#  define REC_API
#endif
typedef int (*rec_cb)(void *ctx, const char *msg);
enum rec_kind { REC_A = 1, REC_B = 1 << 2, REC_C };
REC_API int rec_open(const char *path, rec_cb cb);
extern char rec_table[];
#endif /* REC_H */
"#;

/// Stray characters a mistyped or mis-terminated file can put anywhere:
/// two- and three-byte UTF-8, a four-byte emoji, a combining mark, bidi and
/// zero-width controls, a BOM mid-file, CJK.
const STRAY: &[(&str, &str)] = &[
    ("latin1", "é"),
    ("combining", "e\u{0301}"),
    ("euro", "€"),
    ("emoji", "😀"),
    ("bidi_rlo", "\u{202e}"),
    ("bidi_isolate", "\u{2066}x\u{2069}"),
    ("zwsp", "\u{200b}"),
    ("bom", "\u{feff}"),
    ("cjk", "中文"),
    ("cyrillic_o", "о"),
];

/// `base` with the first `from` replaced by `to`; `from` must occur.
fn replace_once(base: &str, from: &str, to: &str) -> String {
    assert!(base.contains(from), "case table: {from:?} not in base");
    base.replacen(from, to, 1)
}

/// `base` cut just after the first `marker` plus `extra` bytes.
fn cut_after(base: &str, marker: &str, extra: usize) -> Vec<u8> {
    let at = base.find(marker).expect("case table: marker not in base") + extra;
    base.as_bytes()[..at.min(base.len())].to_vec()
}

/// A deterministic run of `n` bytes from `rng`.
fn noise(rng: &mut Rng, n: usize) -> Vec<u8> {
    (0..n).map(|_| rng.next() as u8).collect()
}

/// The fixed table: every malformation class this suite covers, on the base
/// files.
fn table_cases(rng: &mut Rng) -> Vec<Case> {
    let b = BASE_FUNCTION;
    let h = BASE_HEADER;
    let mut out: Vec<Case> = Vec::new();
    let mut add = |name: &str, bytes: Vec<u8>| {
        out.push(Case::new(
            format!("t_{name}.c"),
            bytes,
            format!("table: {name}"),
        ));
    };

    // Unterminated literals and comments.
    add(
        "unterminated_string",
        replace_once(b, "\"copied\"", "\"copied").into(),
    );
    add(
        "unterminated_string_eof",
        format!("{b}const char *s = \"never closed").into(),
    );
    add("unterminated_char", replace_once(b, "'\\0'", "'\\0").into());
    add(
        "unterminated_block_comment",
        replace_once(b, "*/", "").into(),
    );
    add(
        "unterminated_comment_eof",
        format!("{b}/* never closed").into(),
    );
    add(
        "string_holds_brackets",
        replace_once(b, "\"copied\"", "\"]) }{ ([\"").into(),
    );
    add(
        "comment_holds_brackets",
        replace_once(b, "/* the name", "/* ]) }{ ([ the name").into(),
    );

    // Unbalanced brackets.
    add(
        "missing_close_brace",
        b.trim_end().trim_end_matches('}').into(),
    );
    add(
        "missing_close_paren",
        replace_once(b, "if (src == NULL)", "if (src == NULL").into(),
    );
    add(
        "missing_close_bracket",
        replace_once(b, "local[32];", "local[32;").into(),
    );
    add(
        "missing_open_brace",
        replace_once(b, "size_t n) {", "size_t n)").into(),
    );
    add("extra_closers", format!("{b}}}}})));]]\n").into());
    add("closers_first", format!(")]}}{b}").into());

    // Truncation mid-token, mid-literal, mid-directive and mid-UTF-8.
    add("truncated_mid_identifier", cut_after(b, "strncpy", 3));
    add("truncated_mid_string", cut_after(b, "\"copied", 2));
    add("truncated_mid_directive", cut_after(b, "#define MAX(a", 0));
    add("truncated_after_backslash", cut_after(b, "\\n", 1));
    add("truncated_mid_utf8", {
        let mut v = replace_once(b, "local", "lo😀cal").into_bytes();
        let at = v.windows(2).position(|w| w == [b'o', 0xf0]).unwrap() + 3;
        v.truncate(at);
        v
    });
    add("backslash_at_eof", format!("{b}#define TAIL 1 \\").into());
    add(
        "line_splice_mid_keyword",
        replace_once(b, "return -1;", "ret\\\nurn -1;").into(),
    );

    // Encodings and line endings.
    add("bom", format!("\u{feff}{b}").into());
    add("bom_only", "\u{feff}".into());
    add("crlf", b.replace('\n', "\r\n").into());
    add("lone_cr", b.replace('\n', "\r").into());
    add(
        "mixed_line_endings",
        b.split('\n')
            .enumerate()
            .map(|(i, l)| format!("{l}{}", ["\n", "\r\n", "\r"][i % 3]))
            .collect::<String>()
            .into(),
    );
    add(
        "crlf_unterminated_comment",
        replace_once(b, "*/", "").replace('\n', "\r\n").into(),
    );
    add("nul_mid_file", {
        let mut v = b.as_bytes().to_vec();
        v.insert(b.find("int i;").unwrap(), 0);
        v
    });
    add("invalid_utf8", {
        let mut v = b.as_bytes().to_vec();
        let at = b.find("local[i").unwrap();
        v.splice(at..at, [0xff, 0xfe, 0xc3, 0x28, 0xa0, 0xa1]);
        v
    });
    add("surrogate_and_overlong", {
        let mut v = b.as_bytes().to_vec();
        let at = b.find("total++").unwrap();
        v.splice(at..at, [0xed, 0xa0, 0x80, 0xc0, 0xaf]);
        v
    });
    add("latin1_comment", {
        let mut v = b.as_bytes().to_vec();
        let at = b.find("bounded").unwrap();
        v.splice(at..at, [0xe9, 0xe8, b' ']);
        v
    });

    // Size and shape.
    add("empty", Vec::new());
    add("hash_only", "#".into());
    add("define_only", "#define".into());
    add(
        "very_long_line",
        format!("{b}static const int wide = {};\n", "1, ".repeat(4_000)).into(),
    );
    add(
        "very_long_string",
        format!("{b}const char *s = \"{}\";\n", "é".repeat(8_000)).into(),
    );
    add(
        "very_long_identifier",
        format!("{b}int {};\n", "x".repeat(20_000)).into(),
    );
    add(
        "many_small_functions",
        (0..300)
            .map(|i| format!("int f{i}(int a) {{ return a + {i}; }}\n"))
            .collect::<String>()
            .into(),
    );

    // Preprocessor damage.
    add(
        "define_unterminated_params",
        format!("#define BAD(a, b \n{b}").into(),
    );
    add(
        "if_without_endif",
        format!("#if 1\nint a;\n#ifdef Q\n{b}").into(),
    );
    add(
        "endif_without_if",
        format!("#endif\n#else\n#elif 3\n{b}").into(),
    );
    add(
        "include_unterminated",
        format!("#include \"rec.h\n#include <stdio.h\n{b}").into(),
    );
    add(
        "directive_utf8_name",
        format!("#déf\u{0301}ine X 1\n#define Ω(x) x\n#if Ω(1)\n#endif\n{b}").into(),
    );
    add(
        "digraphs_trigraphs",
        format!("%: define DG 1\n??=define TG 2\nint dg<:3:> = <%1,2,3%>;\n{b}").into(),
    );
    add(
        "stray_punctuation",
        replace_once(b, "int i;", "int @i $j `k \\l;").into(),
    );
    add(
        "kr_definition",
        format!("int old(a, b) int a; char *b; {{ return a + *b; }}\n{b}").into(),
    );

    // Header damage, written as `.h` below.
    let header_cases = [
        (
            "unterminated_guard",
            replace_once(h, "#endif /* REC_H */", ""),
        ),
        ("unterminated_comment", replace_once(h, "*/", "")),
        (
            "utf8_macro_name",
            replace_once(h, "REC_API int", "REC_APÍ int"),
        ),
        ("crlf", h.replace('\n', "\r\n")),
    ];

    // Stray UTF-8 in every kind of position.
    let positions: &[(&str, &str, &str)] = &[
        ("identifier", "local[32]", "lo{}cal[32]"),
        ("after_identifier", "int i;", "int i{};"),
        ("operator", "src[i] != '\\0'", "src[i] !{}= '\\0'"),
        ("between_tokens", "i++)", "i++{})"),
        ("macro_argument", "MAX(i, 3)", "MAX(i{}, 3)"),
        (
            "macro_parameter",
            "#define MAX(a, b)",
            "#define MAX(a{}, b)",
        ),
        (
            "directive_name",
            "#include <string.h>",
            "#inc{}lude <string.h>",
        ),
        ("include_path", "<string.h>", "<str{}ing.h>"),
        ("string", "\"copied\"", "\"co{}pied\""),
        ("char_literal", "'\\0'", "'{}'"),
        ("comment", "/* the name", "/* {} the name"),
        ("number", "32]", "3{}2]"),
        ("struct_field", "int count;", "int co{}unt;"),
    ];
    for (pos, from, to) in positions {
        for (what, s) in STRAY {
            add(
                &format!("stray_{what}_in_{pos}"),
                replace_once(b, from, &to.replace("{}", s)).into(),
            );
        }
    }

    // A file of random printable-and-UTF-8 soup.
    let alphabet: Vec<char> = "{}()[];,#\"'/*\\ \n\tabcxyz0123é😀\u{202e}"
        .chars()
        .collect();
    add(
        "soup",
        (0..5_000)
            .map(|_| *rng.pick(&alphabet))
            .collect::<String>()
            .into(),
    );

    for (name, src) in header_cases {
        out.push(Case::new(
            format!("h_{name}.h"),
            src,
            format!("table: header {name}"),
        ));
    }

    // Paths a Windows checkout or a careless archive produces: spaces,
    // non-ASCII directory and file names, mixed case, CRLF content.
    let crlf = b.replace('\n', "\r\n");
    for (path, recipe) in [
        ("dir with space/p_file with space.c", "path with spaces"),
        ("ünïcödé/p_naïve_é.c", "non-ASCII path"),
        ("Mixed Case/p_MiXeD.c", "mixed-case path"),
        ("中文/p_文件.c", "CJK path"),
    ] {
        out.push(Case::new(
            path,
            crlf.clone(),
            format!("table: {recipe}, CRLF content"),
        ));
    }

    // Non-source input under a source name: the input guard refuses it, with
    // a reason, and the scan goes on.
    let blobs: [(&str, Vec<u8>); 3] = [
        (
            "elf",
            [b"\x7fELF\x02\x01\x01\0".as_slice(), &noise(rng, 4096)].concat(),
        ),
        (
            "gzip",
            [b"\x1f\x8b\x08\0".as_slice(), &noise(rng, 4096)].concat(),
        ),
        (
            "png",
            [b"\x89PNG\r\n\x1a\n".as_slice(), &noise(rng, 4096)].concat(),
        ),
    ];
    for (name, bytes) in blobs {
        let mut c = Case::new(
            format!("blob_{name}.c"),
            bytes,
            format!("table: {name} blob named .c"),
        );
        c.refuse = Refuse::Must;
        out.push(c);
    }
    out
}

/// Every rule's `.c` and `.h` fixture, sorted so a seed picks the same files
/// on every machine.
fn rule_fixtures() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.components().any(|c| c.as_os_str() == "tests")
                && matches!(p.extension().and_then(|e| e.to_str()), Some("c" | "h"))
            {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(&repo().join("src/rules"), &mut out);
    out.sort();
    out
}

/// One seeded edit of `s`, and what it did.
fn mutate_once(rng: &mut Rng, s: &mut String) -> String {
    let positions = |s: &str, f: &dyn Fn(char) -> bool| -> Vec<usize> {
        s.char_indices()
            .filter(|(_, c)| f(*c))
            .map(|(i, _)| i)
            .collect()
    };
    let remove_one = |rng: &mut Rng, s: &mut String, at: &[usize]| -> Option<usize> {
        if at.is_empty() {
            return None;
        }
        let i = *rng.pick(at);
        s.remove(i);
        Some(i)
    };
    match rng.below(8) {
        0 => remove_one(rng, s, &positions(s, &|c| c == '"'))
            .map_or("no quote".into(), |i| format!("delete '\"' at {i}")),
        1 => remove_one(rng, s, &positions(s, &|c| c == '\''))
            .map_or("no apostrophe".into(), |i| format!("delete '\\'' at {i}")),
        2 => {
            let ends: Vec<usize> = s.match_indices("*/").map(|(i, _)| i).collect();
            if ends.is_empty() {
                return "no */".into();
            }
            let i = *rng.pick(&ends);
            s.replace_range(i..i + 2, "");
            format!("delete '*/' at {i}")
        }
        3 => remove_one(rng, s, &positions(s, &|c| "{}()[]".contains(c)))
            .map_or("no bracket".into(), |i| format!("delete bracket at {i}")),
        4 | 5 => {
            // Splice stray UTF-8 at a character boundary: anywhere, or right
            // after an identifier character so it lands inside a token.
            let at = if rng.below(2) == 0 {
                positions(s, &|_| true)
            } else {
                s.char_indices()
                    .filter(|(_, c)| c.is_ascii_alphanumeric() || *c == '_')
                    .map(|(i, c)| i + c.len_utf8())
                    .collect()
            };
            let (what, text) = *rng.pick(STRAY);
            let i = if at.is_empty() { 0 } else { *rng.pick(&at) };
            s.insert_str(i, text);
            format!("splice {what} at {i}")
        }
        6 => {
            let at = positions(s, &|c| c == '#');
            if at.is_empty() {
                return "no directive".into();
            }
            // Into the directive name or just after it.
            let start = *rng.pick(&at) + 1;
            let i = s[start..]
                .char_indices()
                .nth(rng.below(8))
                .map_or(s.len(), |(o, _)| start + o);
            let (what, text) = *rng.pick(STRAY);
            s.insert_str(i, text);
            format!("splice {what} into directive at {i}")
        }
        _ => {
            *s = s.replace('\n', "\r\n");
            "CRLF".into()
        }
    }
}

/// `count` seeded mutants of the rule fixtures.
fn mutant_cases(rng: &mut Rng, count: usize) -> Vec<Case> {
    let fixtures = rule_fixtures();
    assert!(
        !fixtures.is_empty(),
        "no rule fixtures found under src/rules"
    );
    let mut out = Vec::new();
    for n in 0..count {
        let path = rng.pick(&fixtures).clone();
        let raw = std::fs::read(&path).unwrap();
        let mut s = String::from_utf8_lossy(&raw).into_owned();
        let mut recipe: Vec<String> = Vec::new();
        for _ in 0..1 + rng.below(3) {
            recipe.push(mutate_once(rng, &mut s));
        }
        let mut bytes = s.into_bytes();
        // Sometimes cut at a BYTE offset, which can split a UTF-8 sequence.
        if !bytes.is_empty() && rng.below(6) == 0 {
            let at = rng.below(bytes.len());
            bytes.truncate(at);
            recipe.push(format!("cut at byte {at}"));
        }
        let rel = path.strip_prefix(repo()).unwrap_or(&path);
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("c");
        out.push(Case::new(
            format!("m{n:04}.{ext}"),
            bytes,
            format!("mutant of {}: {}", rel.display(), recipe.join("; ")),
        ));
    }
    out
}

// -- running -----------------------------------------------------------------

struct Scan {
    /// How the scan ended.
    end: End,
    stderr: String,
    elapsed: Duration,
    /// The scan's peak resident size in KiB, as Linux reports it
    /// (`VmHWM`); `None` where there is no `/proc` to read it from.
    peak_rss_kib: Option<u64>,
}

/// How a scan ended.
#[derive(PartialEq, Eq)]
enum End {
    /// It exited with this code.
    Exited(i32),
    /// A signal ended it: a stack overflow aborts the process (SIGABRT)
    /// before containment can see it.
    Signalled(String),
    /// It ran past its wall limit and the test killed it.
    TimedOut(Duration),
}

/// The all-rules manifest as the scan can read it: copied next to the cases,
/// since a Windows binary cannot open a WSL path.
fn manifest_arg(dir: &Path) -> &'static str {
    std::fs::copy(all_rules_manifest(), dir.join("rules-all.toml")).unwrap();
    "rules-all.toml"
}

/// Scan `dir` with every rule, killing the scan at `limit`.
fn scan_dir(dir: &Path, limit: Duration) -> Scan {
    let manifest = manifest_arg(dir);
    scan_dir_with(dir, manifest, limit)
}

/// Scan `dir` with the manifest `manifest` (a path relative to `dir`),
/// killing the scan at `limit`.
fn scan_dir_with(dir: &Path, manifest: &str, limit: Duration) -> Scan {
    let started = Instant::now();
    // The scan runs from inside the directory and scans `.`: from inside a
    // git checkout (this repository) it would analyse that repository, and
    // a relative path is one a Windows binary run through WSL can resolve.
    let mut child = Command::new(aurora_lint_bin())
        .current_dir(dir)
        .arg(".")
        .arg("-m")
        .arg(manifest)
        .args(["--rule-time-limit", "120"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to execute aurora-lint");
    // Drain stderr on a thread so a chatty scan cannot block on a full pipe.
    let mut err = child.stderr.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = err.read_to_end(&mut s);
        String::from_utf8_lossy(&s).into_owned()
    });
    // Each wait between polls is a fiftieth of the time so far, from 1 ms to
    // 50 ms, so the time read is within 2% of the scan's: a fixed 50 ms made
    // a 100 ms scan's time a multiple of 50 ms, which the size series
    // cannot compare.
    // The high-water mark only rises, so the last reading before the scan
    // exits is its peak, short of what it took in its last poll interval.
    let mut peak_rss_kib = None;
    let end = loop {
        peak_rss_kib = peak_rss(child.id()).or(peak_rss_kib);
        if let Some(status) = child.try_wait().unwrap() {
            break match status.code() {
                Some(code) => End::Exited(code),
                None => End::Signalled(status.to_string()),
            };
        }
        if started.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            break End::TimedOut(limit);
        }
        std::thread::sleep(
            (started.elapsed() / 50).clamp(Duration::from_millis(1), Duration::from_millis(50)),
        );
    };
    Scan {
        end,
        stderr: reader.join().unwrap(),
        elapsed: started.elapsed(),
        peak_rss_kib,
    }
}

/// Process `pid`'s peak resident size in KiB so far, from Linux's
/// `/proc/PID/status`. `None` elsewhere, and for a Windows build run
/// through WSL, whose memory the Linux side does not see.
fn peak_rss(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// `kib` as megabytes for a report, or `?` when it was not measured.
fn megabytes(kib: Option<u64>) -> String {
    kib.map_or_else(|| "?".into(), |k| format!("{:.0}", k as f64 / 1024.0))
}

/// What one line of a scan's stderr says about whether the scan finished.
#[derive(PartialEq, Eq)]
enum Line {
    /// The input guard refused a file: `input skipped (CAUSE): FILE: ...`.
    Refused,
    /// The closing `scan INCOMPLETE` summary, which follows any failure.
    Summary,
    /// Anything else that marks the scan incomplete or failed: a crash, a
    /// step or time limit, an analysis cap, the watchdog's `hang:`, a cause
    /// word this suite does not know yet, or any other `Error:` line.
    Failure,
    /// Progress, warnings and notes.
    Other,
}

/// Classify a stderr line. Every incomplete-scan line is a [`Line::Failure`]
/// unless it is listed here as tolerated: this is an allowlist, so a new
/// cause or message fails the suite until someone decides it is benign.
fn classify(line: &str) -> Line {
    let Some(error) = line.strip_prefix("Error: ") else {
        return Line::Other;
    };
    if error.starts_with("input skipped (") {
        Line::Refused
    } else if error.starts_with("scan INCOMPLETE") {
        Line::Summary
    } else {
        Line::Failure
    }
}

/// Which case a stderr line names: the longest case path the line holds,
/// with either separator, so `a/x.c` never claims a line about `b/a/x.c`.
/// The scan prints paths relative to `.`, as `x.c`, `./x.c` or `.\\x.c`.
fn case_named<'a>(cases: &'a [Case], line: &str) -> Option<&'a Case> {
    cases
        .iter()
        .filter(|c| {
            let windows = c.name.replace('/', "\\");
            [' ', '/', '\\'].iter().any(|before| {
                line.contains(&format!("{before}{}:", c.name))
                    || line.contains(&format!("{before}{windows}:"))
            })
        })
        .max_by_key(|c| c.name.len())
}

/// Keep the inputs that failed, with their recipes, and say where.
fn keep_failures(label: &str, failed: &[&Case]) -> PathBuf {
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(|d| repo().join(d))
        .unwrap_or_else(|| repo().join("target"));
    let keep = target.join("robustness-failures").join(label);
    let _ = std::fs::remove_dir_all(&keep);
    std::fs::create_dir_all(&keep).unwrap();
    let mut index = String::new();
    for c in failed {
        std::fs::write(keep.join(c.name.replace('/', "__")), &c.bytes).unwrap();
        let _ = writeln!(index, "{}\t{}", c.name, c.recipe);
    }
    std::fs::write(keep.join("RECIPES.txt"), index).unwrap();
    keep
}

/// Write `cases` to a fresh directory, scan it, and fail with every bug line,
/// the case and recipe behind each, and how to reproduce the run. Returns
/// the scan, for a caller that reports its time or memory.
fn assert_scans_cleanly(label: &str, cases: &[Case], how: &str, limit: Duration) -> Scan {
    assert_scans_cleanly_with(label, cases, how, limit, None)
}

/// [`assert_scans_cleanly`], under the rules `manifest` enables instead of
/// every rule when it is given.
fn assert_scans_cleanly_with(
    label: &str,
    cases: &[Case],
    how: &str,
    limit: Duration,
    manifest: Option<&Path>,
) -> Scan {
    let dir = tempfile::tempdir().unwrap();
    let mut names = BTreeMap::new();
    for c in cases {
        assert!(
            names.insert(c.name.as_str(), ()).is_none(),
            "duplicate case {}",
            c.name
        );
        let path = dir.path().join(&c.name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, &c.bytes).unwrap();
    }
    let scan = match manifest {
        None => scan_dir(dir.path(), limit),
        Some(manifest) => {
            std::fs::copy(manifest, dir.path().join("rules.toml")).unwrap();
            scan_dir_with(dir.path(), "rules.toml", limit)
        }
    };

    let mut problems: Vec<String> = Vec::new();
    let mut failed: Vec<&Case> = Vec::new();
    match &scan.end {
        End::TimedOut(limit) => problems.push(format!(
            "the scan did not finish within {limit:?} and was killed \
             (AURORA_LINT_ROBUSTNESS_WALL_SECS raises the limit)"
        )),
        End::Signalled(how) => problems.push(format!(
            "the scan was ended by a signal ({how}); a stack overflow aborts \
             the process before containment can see it"
        )),
        // 134 is how a shell, or a Windows build, reports the same abort.
        End::Exited(code) if !matches!(code, 0 | 1 | 3) => {
            problems.push(format!("the scan exited {code}, not 0, 1 or 3"))
        }
        End::Exited(_) => {}
    }
    let mut refusals = 0;
    for line in scan.stderr.lines() {
        let case = case_named(cases, line);
        match classify(line) {
            Line::Refused if case.is_some_and(|c| c.refuse != Refuse::Never) => refusals += 1,
            Line::Refused => {
                problems.push(format!("refused a source file: {line}"));
                failed.extend(case);
            }
            Line::Failure => {
                problems.push(line.to_string());
                failed.extend(case);
            }
            Line::Summary | Line::Other => {}
        }
    }
    for c in cases.iter().filter(|c| c.refuse == Refuse::Must) {
        if !scan.stderr.lines().any(|l| {
            classify(l) == Line::Refused && case_named(cases, l).is_some_and(|x| x.name == c.name)
        }) {
            problems.push(format!("{} ({}) was not refused", c.name, c.recipe));
        }
    }
    // Exit 3 is right only when the one thing incomplete is a file the
    // input guard was meant to refuse.
    if scan.end == End::Exited(3) && problems.is_empty() && refusals == 0 {
        problems.push("exit 3 with no failure line this suite recognises".into());
    }
    if problems.is_empty() {
        return scan;
    }
    // A scan a signal ended, or a panic outside containment exited (101),
    // names no case (the abort comes before any failure line), so keep them
    // all: the culprit is among them.
    let crashed = !matches!(scan.end, End::Exited(0 | 1 | 3));
    if failed.is_empty() && crashed {
        failed.extend(cases);
    }
    failed.sort_by(|a, b| a.name.cmp(&b.name));
    failed.dedup_by(|a, b| a.name == b.name);
    let keep = keep_failures(label, &failed);
    let mut msg = format!(
        "\n{} problem(s) scanning {} {label} case(s) ({how}; {:.1?}, peak {} MB):\n",
        problems.len(),
        cases.len(),
        scan.elapsed,
        megabytes(scan.peak_rss_kib)
    );
    for p in &problems {
        let _ = writeln!(msg, "  {p}");
    }
    let _ = writeln!(msg, "cases:");
    for c in &failed {
        let _ = writeln!(msg, "  {}: {}", c.name, c.recipe);
    }
    let _ = writeln!(
        msg,
        "inputs kept in {}\nreproduce one: cargo run -- -m rules_templates/rules-all.toml {}/<case>",
        keep.display(),
        keep.display()
    );
    // A panic that escaped containment prints its message (the line after
    // `panicked at`) wherever it fell in the output, maybe above the tail.
    if crashed {
        let lines: Vec<&str> = scan.stderr.lines().collect();
        for (i, l) in lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.contains("panicked at"))
        {
            let _ = writeln!(msg, "panic:\n  {l}");
            if let Some(next) = lines.get(i + 1) {
                let _ = writeln!(msg, "  {next}");
            }
        }
    }
    if !failed.is_empty() || crashed {
        let tail: Vec<&str> = scan.stderr.lines().rev().take(20).collect();
        let _ = writeln!(
            msg,
            "stderr tail:\n  {}",
            tail.into_iter().rev().collect::<Vec<_>>().join("\n  ")
        );
    }
    panic!("{msg}");
}

#[test]
fn malformed_input_table_scans_without_a_crash() {
    let _runner = untimed();
    let seed = env_or("AURORA_LINT_ROBUSTNESS_SEED", DEFAULT_SEED);
    let cases = table_cases(&mut Rng(seed));
    assert_scans_cleanly(
        "table",
        &cases,
        &format!("AURORA_LINT_ROBUSTNESS_SEED={seed}"),
        wall_limit(SCAN_WALL_LIMIT),
    );
}

#[test]
fn mutated_rule_fixtures_scan_without_a_crash() {
    let _runner = untimed();
    let seed = env_or("AURORA_LINT_ROBUSTNESS_SEED", DEFAULT_SEED);
    let count = env_or("AURORA_LINT_ROBUSTNESS_MUTANTS", DEFAULT_MUTANTS);
    // A different stream from the table's, so the two never share choices.
    let cases = mutant_cases(&mut Rng(seed ^ 0x6d75_7461_6e74), count);
    assert_scans_cleanly(
        "mutants",
        &cases,
        &format!("AURORA_LINT_ROBUSTNESS_SEED={seed} AURORA_LINT_ROBUSTNESS_MUTANTS={count}"),
        wall_limit(SCAN_WALL_LIMIT),
    );
}

/// Inputs that once ended a scan, kept as they were found: one directory
/// under `tests/fixtures/robustness/` each, holding the input and a
/// `rules.toml` enabling the rules it crashed. Each is scanned by the binary
/// this `cargo test` built, which in a debug build has the deep frames the
/// crash needed, on the scan's own stack: the raised stack the in-process
/// fixture tests run on would hide a stack overflow. Only the crashing rules
/// run, so the case costs seconds rather than every rule's minutes.
#[test]
fn inputs_that_once_crashed_scan_without_a_crash() {
    let _runner = untimed();
    let root = repo().join("tests/fixtures/robustness");
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    assert!(!dirs.is_empty(), "no kept inputs under {}", root.display());
    for dir in dirs {
        let label = dir.file_name().unwrap().to_string_lossy().into_owned();
        let mut cases: Vec<Case> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "c" || x == "h"))
            .map(|p| {
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                let recipe = format!("kept input tests/fixtures/robustness/{label}/{name}");
                Case::new(name, std::fs::read(&p).unwrap(), recipe)
            })
            .collect();
        cases.sort_by(|a, b| a.name.cmp(&b.name));
        assert_scans_cleanly_with(
            &format!("kept-{label}"),
            &cases,
            &format!("kept inputs {label}"),
            wall_limit(SCAN_WALL_LIMIT),
            Some(&dir.join("rules.toml")),
        );
    }
}

/// Every rule's fixtures, scanned together under the FULL rule set. A rule's
/// own fixture tests run that rule alone on its own fixtures, which never
/// showed one rule crashing on another rule's fixtures, nor what only a
/// many-file scan reaches (the cross-file prescan, the worker pool).
///
/// Ten minutes or more in a debug build, and growing with every fixture
/// added, so it runs in CI's release robustness job rather than in every
/// `cargo test`. It is also the only run that scans the fixtures written
/// for fixed crashes under every rule, so it is what catches those
/// regressions.
#[test]
#[ignore = "every fixture under every rule: run in release with --ignored (CI robustness job)"]
fn every_rule_fixture_scans_under_every_rule() {
    let _runner = untimed();
    let cases: Vec<Case> = rule_fixtures()
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(repo().join("src/rules"))
                .unwrap()
                .to_path_buf();
            let name = rel.to_string_lossy().replace('\\', "/");
            Case::new(name, std::fs::read(&p).unwrap(), "fixture, unchanged")
        })
        .collect();
    assert_scans_cleanly(
        "fixtures",
        &cases,
        "every rule fixture",
        wall_limit(FIXTURES_WALL_LIMIT),
    );
}

/// `int x = 1 + 1 + ... + 1;`, `terms` additions long.
fn binary_chain(terms: usize) -> Vec<u8> {
    format!("int x = {}1;\n", "1 + ".repeat(terms)).into_bytes()
}

/// One function whose body is an `if` and `branches - 1` `else if`s, each
/// nested in the last.
fn else_if_ladder(branches: usize) -> Vec<u8> {
    format!(
        "int g(int a) {{ if (a == 0) return 0;{} return -1; }}\n",
        (1..branches)
            .map(|i| format!(" else if (a == {i}) return {i};"))
            .collect::<String>()
    )
    .into_bytes()
}

/// One loop in which a pointer is reassigned from itself in `branches`
/// branches (`if (c == i) p = p + i;`), then written through. Each
/// assignment's value names the pointer again, so a trace of where it may
/// point that asks each reaching value's own reaching values, and remembers
/// nothing, re-asks the same questions by every path: exponential in the
/// branches, where it must be about quadratic.
fn self_reassigned_pointer(branches: usize) -> Vec<u8> {
    format!(
        "void f(char *buf, int c) {{\n    char *p = buf;\n    while (c--) {{\n{}        *p = 'x';\n    }}\n}}\n",
        (0..branches)
            .map(|i| format!("        if (c == {i}) p = p + {i};\n"))
            .collect::<String>()
    )
    .into_bytes()
}

/// One straight-line function of `blocks` repetitions of "assign a local
/// pointer, pass its address to a call, read it", as generated initializer
/// code is written. Every read replays the block's statements before it; a
/// replay that finds each statement by walking the function body's children
/// is cubic in the length.
fn address_taken_reassignments(blocks: usize) -> Vec<u8> {
    format!(
        "struct o {{ int x; }};\nextern struct o g[{blocks}];\nvoid intern(struct o **);\n\
         int check(struct o *);\nvoid init(void) {{\n    struct o *s;\n{}}}\n",
        (0..blocks)
            .map(|i| format!("    s = &g[{i}];\n    intern(&s);\n    check(s);\n"))
            .collect::<String>()
    )
    .into_bytes()
}

/// `calls` debug-print calls, each passing two named arguments, spread over
/// functions of 100: a generated parser's tracing. A rule that looks each
/// argument's type up in the whole file's text, re-reading the file per
/// argument, is quadratic in the file here.
fn format_calls(calls: usize) -> Vec<u8> {
    let mut out = String::from("#include <stdio.h>\n");
    for f in 0..calls.div_ceil(100) {
        let _ = writeln!(out, "void trace{f}(int level, const char *rule) {{");
        for i in 0..100.min(calls - f * 100) {
            let _ = writeln!(out, "    fprintf(stderr, \"%d %s {i}\\n\", level, rule);");
        }
        out.push_str("}\n");
    }
    out.into_bytes()
}

/// An `else if` ladder `branches` long whose conditions call a function-like
/// macro on a local, as a command-line completer's matching is written.
/// Every argument is an identifier to resolve thousands of levels deep, and
/// `Node::parent()` recovers a parent by descending from the root, so a
/// lookup that climbs to its scope per identifier is cubic here.
fn macro_call_ladder(branches: usize) -> Vec<u8> {
    format!(
        "#define MATCH(v, k) ((v) == (k))\nint g(int a) {{\n    int x = a;\n    \
         if (MATCH(x, 0)) return 0;{} return -1;\n}}\n",
        (1..branches)
            .map(|i| format!(" else if (MATCH(x, {i})) return {i};"))
            .collect::<String>()
    )
    .into_bytes()
}

/// `rows` designated-initializer rows with no enclosing declaration or
/// function, as a generated table fragment meant to be `#include`d inside an
/// array initializer is written. Not valid C on its own, it parses to a tree
/// whose depth grows with the rows, so a rule that climbs `Node::parent()`
/// from each identifier or initializer to the root is cubic here.
fn table_fragment(rows: usize) -> Vec<u8> {
    (0..rows)
        .map(|i| {
            format!(
                "{{ .op = OP_{}, .size = {}, .type = KIND_A, .mask = 0x{i:04x} }},\n",
                i % 37,
                8 << (i % 2)
            )
        })
        .collect::<String>()
        .into_bytes()
}

/// Long expressions and `else if` ladders at lengths real code reaches
/// (generated tables, state machines, unrolled arithmetic). A rule that asks
/// a whole-subtree question at each operator, or climbs `Node::parent()`
/// from each one, is cubic in the length here: a 1000-term `1 + 1 + ...` once
/// ran the integer rules past the watchdog, which ends the whole scan. The
/// same holds for generated straight-line code, self-referential assignments
/// in a loop, generated tracing, macro-call ladders and table fragments
/// ([`self_reassigned_pointer`], [`address_taken_reassignments`],
/// [`format_calls`], [`macro_call_ladder`], [`table_fragment`]).
fn long_chain_cases() -> Vec<Case> {
    let case = |name: &str, bytes: Vec<u8>| Case::new(format!("c_{name}.c"), bytes, name);
    vec![
        case("binary_chain_1000_long", binary_chain(1_000)),
        case("else_if_1000_long", else_if_ladder(1_000)),
        // Identifiers make each operand a declaration to resolve as well.
        case(
            "identifier_chain_100_long",
            format!(
                "int f(int a, unsigned u) {{ return {}a; }}\n",
                "a + u * ".repeat(100)
            )
            .into_bytes(),
        ),
        case(
            "self_reassigned_pointer_100_branches",
            self_reassigned_pointer(100),
        ),
        case(
            "address_taken_reassignments_800_long",
            address_taken_reassignments(800),
        ),
        case("format_calls_20000", format_calls(20_000)),
        case("macro_call_ladder_1000_long", macro_call_ladder(1_000)),
        case("table_fragment_400_rows", table_fragment(400)),
    ]
}

/// Nesting from a thousand levels to a million: braces, parentheses, an
/// operator chain and an `else if` ladder. A thousand is analysed; past
/// `--max-nesting-depth` (5000 tree levels by default) the file must be
/// refused with its depth. Analyses walk the tree recursively, and a stack
/// overflow aborts the whole process before containment can report it, so
/// before the guard ten thousand levels of any of these ended the scan.
///
/// Just under the limit each shape must still be analysed by every rule
/// within its time limit: 4990 levels, or 2490 `else if` branches at two
/// levels each. A rule that climbs `Node::parent()` (which costs the node's
/// depth) from every node, or asks a whole-subtree question at each
/// operator, is quadratic or cubic in the depth here, and several ran past
/// the limit before this case was added. The operator chain is a file-scope
/// initializer; in a function body several rules are still superlinear in
/// its length, so that shape is not a case yet.
fn deep_nesting_cases() -> Vec<Case> {
    let mut out = vec![
        Case::new(
            "n_braces_4990_deep.c",
            format!("void h(void) {}{}\n", "{".repeat(4_990), "}".repeat(4_990)),
            "braces_4990_deep",
        ),
        Case::new(
            "n_parens_4990_deep.c",
            format!("int y = {}1{};\n", "(".repeat(4_990), ")".repeat(4_990)),
            "parens_4990_deep",
        ),
        Case::new(
            "n_binary_chain_4990_long.c",
            binary_chain(4_990),
            "binary_chain_4990_long",
        ),
        Case::new(
            "n_else_if_2490_long.c",
            else_if_ladder(2_490),
            "else_if_2490_long",
        ),
        Case::new(
            "n_ifs_2400_deep.c",
            format!(
                "void h(int x) {{ {}{} }}\n",
                "if (x) { ".repeat(2_400),
                "} ".repeat(2_400)
            ),
            "ifs_2400_deep",
        ),
    ];
    for depth in [1_000, 10_000, 100_000, 1_000_000] {
        let refuse = if depth > 1_000 {
            Refuse::Must
        } else {
            Refuse::Never
        };
        let mut add = |name: String, bytes: Vec<u8>| {
            let mut c = Case::new(format!("n_{name}.c"), bytes, name);
            c.refuse = refuse;
            out.push(c);
        };
        add(
            format!("braces_{depth}_deep"),
            format!("void h(void) {}{}\n", "{".repeat(depth), "}".repeat(depth)).into_bytes(),
        );
        add(
            format!("parens_{depth}_deep"),
            format!("int y = {}1{};\n", "(".repeat(depth), ")".repeat(depth)).into_bytes(),
        );
        // At 1000 these two are [`long_chain_cases`]. A million-branch
        // ladder is a 37 MiB file whose parse alone takes 2 GiB, which buys
        // nothing over the 100,000 one, 200,000 levels deep.
        if depth > 1_000 {
            add(format!("binary_chain_{depth}_long"), binary_chain(depth));
        }
        if depth > 1_000 && depth <= 100_000 {
            add(format!("else_if_{depth}_long"), else_if_ladder(depth));
        }
    }
    out
}

#[test]
#[ignore = "deep nesting under every rule: run in release with --ignored (CI robustness job)"]
fn deep_nesting_is_refused_or_analysed() {
    let _runner = untimed();
    assert_scans_cleanly(
        "nesting",
        &deep_nesting_cases(),
        "deep nesting",
        wall_limit(SCAN_WALL_LIMIT),
    );
}

#[test]
#[ignore = "long chains under every rule: run in release with --ignored (CI robustness job)"]
fn long_chains_scan_within_budget() {
    let _runner = untimed();
    assert_scans_cleanly(
        "chains",
        &long_chain_cases(),
        "long chains",
        wall_limit(SCAN_WALL_LIMIT),
    );
}

/// How long the 100,000-deep `#define` chain may take under every rule. A
/// linear scan takes under a minute, alone on the runner ([`timed`]), which
/// leaves room for a slower CI runner; valuing the macros in rounds, one
/// more link of the chain per round, takes longer than this for that one
/// rule alone.
const MACRO_CHAIN_WALL_LIMIT: Duration = Duration::from_secs(180);

/// A chain of 100,000 object-like macros, each defined from the one before,
/// under every rule within [`MACRO_CHAIN_WALL_LIMIT`]. A rule that values the
/// macros in rounds, one more link of the chain per round, is quadratic in
/// its depth and once ran a chain this deep past the watchdog. The deeper
/// chains of [`large_cases`] cost minutes and gigabytes even when linear,
/// so this one stands in for them in CI.
#[test]
#[ignore = "a deep #define chain under every rule: run in release with --ignored (CI robustness job)"]
fn deep_macro_chain_scans_within_budget() {
    let _runner = timed();
    assert_scans_cleanly(
        "macro_chain",
        &[Case::new(
            "c_macro_chain_100000_deep.c",
            define_chain(100_000),
            "macro_chain_100000_deep",
        )],
        "a deep macro chain",
        wall_limit(MACRO_CHAIN_WALL_LIMIT),
    );
}

/// How long a large case may take per byte of input, in microseconds:
/// three times the slowest rate measured, so a slower or busier runner
/// still passes and a step that grows faster than the input does not. Every
/// rule scanning one file is linear in its size, at 93 us/B for a file of
/// one-line functions (8 MiB in 780 s) and 52 us/B for one line of
/// declarations (21.8 MB in 1127 s) on the slowest machine measured, and at
/// 65 and 35 us/B on another: every rule walks the whole file, so a larger
/// file costs proportionally more however few findings it holds. A single
/// wall limit either fails large linear inputs on a slower machine or is too
/// loose to mean anything for small ones;
/// [`every_rule_size_series_scales_near_linearly`] is what catches a step
/// that grows faster than the input.
const LARGE_CASE_MICROS_PER_BYTE: u64 = 280;

/// The most any one large case may take, so a hand-run test ends: a case
/// built to be refused that is not would otherwise be given hours.
const LARGE_CASE_MAX_WALL: Duration = Duration::from_secs(2 * 3600);

/// The default `--max-file-size`, in bytes: a larger file is refused unread.
const DEFAULT_MAX_FILE_BYTES: usize = 64 * 1024 * 1024;

/// Whether `case` is analysed at all: the input guard refuses a case built
/// to be refused, and any file over the size limit, before reading it.
fn large_case_is_analysed(case: &Case) -> bool {
    case.refuse != Refuse::Must && case.bytes.len() <= DEFAULT_MAX_FILE_BYTES
}

/// The wall limit for `case`: [`LARGE_CASE_MICROS_PER_BYTE`] of its size,
/// between [`SCAN_WALL_LIMIT`] and [`LARGE_CASE_MAX_WALL`]. A case that is
/// never analysed keeps [`SCAN_WALL_LIMIT`], since its size buys it nothing.
fn large_case_wall_limit(case: &Case) -> Duration {
    if !large_case_is_analysed(case) {
        return SCAN_WALL_LIMIT;
    }
    Duration::from_micros(case.bytes.len() as u64 * LARGE_CASE_MICROS_PER_BYTE)
        .clamp(SCAN_WALL_LIMIT, LARGE_CASE_MAX_WALL)
}

/// Inputs too large or too deep for every `cargo test`: generated at test
/// time, never committed. Each must be refused with a reason or analysed
/// within budget -- never a crash, a hang or a stack overflow, which aborts
/// the scan before containment can see it. Run in release, time-boxed:
/// `cargo test --release --test robustness -- --ignored --show-output`,
/// since a passing test's per-case times and memory print only with
/// `--show-output`.
fn large_cases() -> Vec<Case> {
    let mut rng = Rng(DEFAULT_SEED);
    let mut out = Vec::new();
    let mut add = |name: &str, bytes: Vec<u8>, refuse: Refuse| {
        let mut c = Case::new(format!("l_{name}.c"), bytes, format!("large: {name}"));
        c.refuse = refuse;
        out.push(c);
    };
    let limit = DEFAULT_MAX_FILE_BYTES;
    let function = |i: usize| format!("int f{i}(int a) {{ return a * {i} + 1; }}\n");
    let mut over = String::new();
    let mut i = 0;
    while over.len() <= limit {
        over.push_str(&function(i));
        i += 1;
    }
    add(
        "valid_just_over_size_limit",
        over.into_bytes(),
        Refuse::Must,
    );
    add(
        "valid_eight_mib",
        (0..)
            .map(function)
            .take_while({
                let mut n = 0;
                move |f| {
                    n += f.len();
                    n < 8 * 1024 * 1024
                }
            })
            .collect::<String>()
            .into_bytes(),
        Refuse::Never,
    );
    add(
        "random_bytes_200_mib",
        noise(&mut rng, 200 * 1024 * 1024),
        Refuse::May,
    );
    add(
        "one_sixteen_mib_line",
        (0..)
            .map(|i| format!("int a{i} = {i}; "))
            .take(1_000_000)
            .collect::<String>()
            .into_bytes(),
        Refuse::May,
    );
    // Nesting past `--max-nesting-depth` is in CI: [`deep_nesting_cases`].
    for depth in [1_000, 10_000, 100_000, 1_000_000] {
        add(
            &format!("macro_chain_{depth}_deep"),
            (1..depth)
                .map(|i| format!("#define M{i} (M{} + 1)\n", i - 1))
                .chain([format!("#define M0 1\nint z = M{};\n", depth - 1)])
                .collect::<String>()
                .into_bytes(),
            Refuse::May,
        );
    }
    // The same chain read at a local initializer the function overwrites,
    // which a dead-store rule values through every link: 50,000 links is
    // past the depth at which a recursive walk of the chain overflowed the
    // scan thread's stack.
    for depth in [1_000, 10_000, 50_000] {
        add(
            &format!("macro_chain_{depth}_deep_in_a_function"),
            (1..depth)
                .map(|i| format!("#define M{i} (M{} + 1)\n", i - 1))
                .chain([format!(
                    "#define M0 1\nint get(void);\n\
                     int f(void) {{ int z = M{}; z = get(); return z; }}\n",
                    depth - 1
                )])
                .collect::<String>()
                .into_bytes(),
            Refuse::May,
        );
    }
    out
}

#[test]
#[ignore = "large and deep generated inputs: run in release with --ignored, time-boxed"]
fn large_and_deep_inputs_are_refused_or_analysed_within_budget() {
    let _runner = timed();
    // One scan per case: a stack overflow aborts the whole process, and in a
    // shared scan it would hide every case after it.
    let cases = large_cases();
    let mut failures = Vec::new();
    for c in cases {
        let name = c.name.clone();
        let limit = wall_limit(large_case_wall_limit(&c));
        let megabytes_in = c.bytes.len() as f64 / 1e6;
        let result = std::panic::catch_unwind(|| {
            assert_scans_cleanly(
                "large",
                std::slice::from_ref(&c),
                &format!("large case, limit {limit:.0?}"),
                limit,
            )
        });
        if let Ok(scan) = &result {
            // A refused case's time is the guard's, not a rate per byte.
            let rate = if large_case_is_analysed(&c) {
                let micros = scan.elapsed.as_secs_f64() * 1e6 / c.bytes.len().max(1) as f64;
                format!("{micros:.0} us/B")
            } else {
                "refused unread".into()
            };
            println!(
                "{name}: {megabytes_in:.1} MB in {:.1?} ({rate}, limit {limit:.0?}), peak {} MB",
                scan.elapsed,
                megabytes(scan.peak_rss_kib)
            );
        }
        if let Err(e) = result {
            let msg = e
                .downcast_ref::<String>()
                .cloned()
                .unwrap_or_else(|| "non-string panic".into());
            failures.push(format!("{name}:{msg}"));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// One rule enabled, written next to the cases as `one-rule.toml`.
fn one_rule_manifest(dir: &Path, rule_id: &str) -> &'static str {
    std::fs::write(
        dir.join("one-rule.toml"),
        format!(
            "[metadata]\nname = \"one rule\"\nversion = \"1.0.0\"\n\
             description = \"robustness size series\"\ncert_version = \"2016\"\n\n\
             [rules.cert_c.{rule_id}]\nenabled = true\n"
        ),
    )
    .unwrap();
    "one-rule.toml"
}

/// The steepest growth the size series accepts: the slope of log time over
/// log size, fitted to its four sizes. A linear scan has slope 1; one step
/// that rescans the file per function or per directive costs 30x and more
/// for 8x the input at these sizes, a slope of 1.6 and more, which is what
/// this catches. 1.3 is the earlier bound of 14x for 8x the input, now held
/// by four sizes rather than two; the slack above 1 is for a noisy runner,
/// not for growth.
const SIZE_SERIES_MAX_SLOPE: f64 = 1.3;

/// Rounds of the size series. Each round scans every size once, smallest
/// first, and the fastest scan of each size counts: a burst of load on the
/// runner then slows one round of every size rather than every scan of
/// one size.
const SIZE_SERIES_RUNS: usize = 3;

/// The sizes of the series, as multiples of its smallest.
const SIZE_SERIES_STEPS: [usize; 4] = [1, 2, 4, 8];

/// A file of `bytes` bytes of one-line functions.
fn one_line_functions(bytes: usize) -> Vec<u8> {
    let mut out = String::new();
    let mut i = 0;
    while out.len() < bytes {
        let _ = writeln!(out, "int f{i}(int a) {{ return a * {i} + 1; }}");
        i += 1;
    }
    out.into_bytes()
}

/// A file of `bytes` bytes of file-scope declarations on one line, the
/// shape of the large case `one_sixteen_mib_line`.
fn one_line_declarations(bytes: usize) -> Vec<u8> {
    let mut out = String::new();
    let mut i = 0;
    while out.len() < bytes {
        let _ = write!(out, "int a{i} = {i}; ");
        i += 1;
    }
    out.into_bytes()
}

/// A file of `bytes` bytes of one-line functions, each copying its pointer
/// parameter into a local array.
fn one_line_string_copies(bytes: usize) -> Vec<u8> {
    let mut out = String::from("#include <string.h>\n");
    let mut i = 0;
    while out.len() < bytes {
        let _ = writeln!(
            out,
            "void f{i}(char *in) {{ char buf{i}[16]; strcpy(buf{i}, in); }}"
        );
        i += 1;
    }
    out.into_bytes()
}

/// One function of `bytes` bytes, each line assigning a path variable and
/// opening it to write.
fn one_function_of_creating_opens(bytes: usize) -> Vec<u8> {
    let mut out =
        String::from("#include <stdio.h>\nvoid f(void) {\n    const char *p;\n    FILE *fp;\n");
    let mut i = 0;
    while out.len() < bytes {
        let _ = writeln!(out, "    p = \"/home/u/out{i}\"; fp = fopen(p, \"w\");");
        i += 1;
    }
    out.push_str("}\n");
    out.into_bytes()
}

/// A chain of `depth` object-like macros, each defined from the one before.
fn define_chain(depth: usize) -> Vec<u8> {
    let mut out = String::new();
    for i in 1..depth {
        let _ = writeln!(out, "#define M{i} (M{} + 1)", i - 1);
    }
    let _ = writeln!(out, "#define M0 1\nint z = M{};", depth - 1);
    out.into_bytes()
}

/// A flags macro whose body names one identifier of `length` letters, all
/// `L`, each of which the constant evaluator could strip as an integer
/// suffix.
fn suffix_letter_run(length: usize) -> Vec<u8> {
    format!(
        "#define A ({} | 0)\nvoid f(void) {{ LoadLibraryExW(L\"x.dll\", NULL, A); }}\n",
        "L".repeat(length)
    )
    .into_bytes()
}

/// A chain of `depth` object-like macros, each the one before under
/// another name, with a local initialized from every two-hundredth link
/// and overwritten unread: a dead-store rule reads each such initializer's
/// macro through the whole chain below it to decide whether it is a
/// default.
fn alias_chain_in_functions(depth: usize) -> Vec<u8> {
    let mut out = String::from("int get(void);\n#define M0 0\n");
    for i in 1..depth {
        let _ = writeln!(out, "#define M{i} M{}", i - 1);
    }
    for i in (0..depth).step_by(200) {
        let _ = writeln!(
            out,
            "int f{i}(void) {{ int x = M{i}; x = get(); return x; }}"
        );
    }
    out.into_bytes()
}

/// A chain of `depth` object-like macros, each reading the one before and
/// a parameter of its own function, with a local initialized from every
/// two-hundredth link and overwritten unread: a dead-store rule records
/// which parameters each link's expansion reads, which grows with the
/// chain below it unless bounded.
fn parameter_chain_in_functions(depth: usize) -> Vec<u8> {
    let mut out = String::from("int get(void);\n#define M0 (p0)\n");
    for i in 1..depth {
        let _ = writeln!(out, "#define M{i} (M{} + p{i})", i - 1);
    }
    for i in 0..depth {
        let _ = writeln!(out, "int g{i}(int p{i}) {{ return p{i}; }}");
    }
    for i in (0..depth).step_by(200) {
        let _ = writeln!(
            out,
            "int f{i}(void) {{ int x = M{i}; x = get(); return x; }}"
        );
    }
    out.into_bytes()
}

/// `count` functions, each a chain of 32 fixed-size arrays sized by the
/// `sizeof` of the one before, twice: an array-size rule that reads a
/// `sizeof` operand's own size anew at every reference doubles its work per
/// link.
fn sizeof_chains_in_functions(count: usize) -> Vec<u8> {
    let mut out = String::new();
    for i in 0..count {
        let _ = writeln!(out, "void s{i}(void) {{\n    char a0[4];");
        for k in 1..32 {
            let _ = writeln!(out, "    char a{k}[sizeof a{} + sizeof a{}];", k - 1, k - 1);
        }
        let _ = writeln!(out, "}}");
    }
    out.into_bytes()
}

/// The time of one scan of the files written in `dir` under the manifest
/// `manifest`. A scan that does not finish cleanly fails the test outright.
fn time_one_scan(dir: &Path, manifest: &str, what: &str) -> Duration {
    let scan = scan_dir_with(dir, manifest, wall_limit(SCAN_WALL_LIMIT));
    assert!(
        matches!(scan.end, End::Exited(0 | 1)),
        "{what} did not finish cleanly; stderr tail:\n{}",
        scan.stderr
            .lines()
            .rev()
            .take(10)
            .collect::<Vec<_>>()
            .join("\n")
    );
    scan.elapsed
}

/// The least-squares slope of `ln t` over `ln n` for the points `(n, t)`:
/// how fast the time grows with the size, 1 for linear and 2 for quadratic.
fn log_log_slope(points: &[(usize, Duration)]) -> f64 {
    let xy: Vec<(f64, f64)> = points
        .iter()
        .map(|&(n, t)| ((n as f64).ln(), t.as_secs_f64().max(0.001).ln()))
        .collect();
    let mx = xy.iter().map(|p| p.0).sum::<f64>() / xy.len() as f64;
    let my = xy.iter().map(|p| p.1).sum::<f64>() / xy.len() as f64;
    let sxy: f64 = xy.iter().map(|&(x, y)| (x - mx) * (y - my)).sum();
    let sxx: f64 = xy.iter().map(|&(x, _)| (x - mx) * (x - mx)).sum();
    sxy / sxx
}

/// One size series: a name, the one rule to scan under (`None` for every
/// rule), the generator, and the smallest size it is given.
type Series = (
    &'static str,
    Option<&'static str>,
    fn(usize) -> Vec<u8>,
    usize,
);

/// The fastest time of each size of one series, in [`SIZE_SERIES_STEPS`]
/// order: every size written to a directory of its own, then
/// [`SIZE_SERIES_RUNS`] rounds that scan each size once under one rule, or
/// under every rule when `rule_id` is `None`.
fn time_series(
    name: &str,
    rule_id: Option<&str>,
    generate: fn(usize) -> Vec<u8>,
    small: usize,
) -> Vec<(usize, Duration)> {
    let sizes: Vec<(usize, tempfile::TempDir, &str)> = SIZE_SERIES_STEPS
        .iter()
        .map(|&step| {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join(format!("{name}_{step}x.c")),
                generate(step * small),
            )
            .unwrap();
            let manifest = match rule_id {
                Some(rule_id) => one_rule_manifest(dir.path(), rule_id),
                None => manifest_arg(dir.path()),
            };
            (step * small, dir, manifest)
        })
        .collect();
    let mut fastest = vec![Duration::MAX; sizes.len()];
    for _ in 0..SIZE_SERIES_RUNS {
        for (i, (size, dir, manifest)) in sizes.iter().enumerate() {
            let what = format!("{name} ({size}) under {}", rule_id.unwrap_or("every rule"));
            fastest[i] = fastest[i].min(time_one_scan(dir.path(), manifest, &what));
        }
    }
    sizes.iter().map(|s| s.0).zip(fastest).collect()
}

/// Generated inputs at four sizes, from the smallest to eight times it, each
/// scanned under the one rule that exercises what grows: the prescan runs
/// whatever rule is enabled, so a file of one-line functions under MSC04-C
/// times the per-function prescan steps, the same file under INT34-C times
/// the per-function value-range analysis the integer rules share, a file of
/// one-line `strcpy` functions under STR31-C times that rule's per-call
/// buffer-size lookups, one long function of `fopen` calls under FIO21-C
/// times that rule's per-open callee resolution and path tracing, a deep
/// `#define` chain under PRE32-C times that rule's per-directive work, a
/// name made of one long run of `L` under WIN00-C times that rule's reading
/// of the names a flags macro may use, a deep chain of macro aliases, or of
/// macros each reading a parameter, read at local initializers under MSC13-C
/// times its reading of each macro, and functions of `sizeof`-sized array
/// chains under MEM05-C time its reading of each array size.
/// Each series' time must grow no faster than [`SIZE_SERIES_MAX_SLOPE`]
/// over its sizes, so a step that rescans the whole file per item fails
/// here rather than as a watchdog hang on a large real file. Every series'
/// times and slope are printed, passing or not, so a near miss shows in
/// the CI log.
#[test]
#[ignore = "size series: run in release with --ignored (CI robustness job)"]
fn generated_size_series_scale_near_linearly() {
    let _runner = timed();
    let series: [Series; 9] = [
        (
            "one_line_functions",
            Some("MSC04-C"),
            one_line_functions,
            256 * 1024,
        ),
        (
            "one_line_functions",
            Some("INT34-C"),
            one_line_functions,
            128 * 1024,
        ),
        (
            "one_line_string_copies",
            Some("STR31-C"),
            one_line_string_copies,
            8 * 1024,
        ),
        (
            "one_function_of_creating_opens",
            Some("FIO21-C"),
            one_function_of_creating_opens,
            4 * 1024,
        ),
        ("define_chain", Some("PRE32-C"), define_chain, 10_000),
        (
            "suffix_letter_run",
            Some("WIN00-C"),
            suffix_letter_run,
            40_000,
        ),
        (
            "alias_chain_in_functions",
            Some("MSC13-C"),
            alias_chain_in_functions,
            5_000,
        ),
        (
            "parameter_chain_in_functions",
            Some("MSC13-C"),
            parameter_chain_in_functions,
            1_000,
        ),
        (
            "sizeof_chains_in_functions",
            Some("MEM05-C"),
            sizeof_chains_in_functions,
            200,
        ),
    ];
    assert_series_near_linear(&series);
}

/// Time every series in `series` and fail any whose time against size has a
/// log-log slope above [`SIZE_SERIES_MAX_SLOPE`]. Every series' times and slope are printed,
/// passing or not, so a near miss shows in the log.
fn assert_series_near_linear(series: &[Series]) {
    let mut failures = Vec::new();
    for &(name, rule_id, generate, small) in series {
        let points = time_series(name, rule_id, generate, small);
        let slope = log_log_slope(&points);
        let times = points
            .iter()
            .map(|(_, t)| format!("{t:.1?}"))
            .collect::<Vec<_>>()
            .join(" -> ");
        let ratio = points[points.len() - 1].1.as_secs_f64() / points[0].1.as_secs_f64().max(0.001);
        let line = format!(
            "{name} under {}: {times} for 1x/2x/4x/8x the input \
             (slope {slope:.2}, 8x took {ratio:.1}x)",
            rule_id.unwrap_or("every rule")
        );
        println!("{line}");
        if slope > SIZE_SERIES_MAX_SLOPE {
            failures.push(format!("{line}, steeper than {SIZE_SERIES_MAX_SLOPE}"));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// The two shapes of the large cases, a file of one-line functions and one
/// line of declarations, scanned under every rule from 64 KiB to 512 KiB.
/// A rule or analysis that does more than a linear amount of work per
/// function or per declaration fails here, under whichever rule it is: the
/// per-rule series above time only the rules picked for them. Every rule
/// scanning one file takes about 65 us per byte of the functions and 35 us
/// per byte of the declaration line, so the largest is a 35 s scan and the
/// test takes about five minutes.
#[test]
#[ignore = "size series: run in release with --ignored (CI robustness job)"]
fn every_rule_size_series_scales_near_linearly() {
    let _runner = timed();
    assert_series_near_linear(&[
        ("one_line_functions", None, one_line_functions, 64 * 1024),
        (
            "one_line_declarations",
            None,
            one_line_declarations,
            64 * 1024,
        ),
    ]);
}

/// [`every_rule_size_series_scales_near_linearly`] at the sizes of the large
/// cases, from 256 KiB to 2 MiB: about twenty minutes, so run by hand with
/// the large cases, not in CI. Its name keeps it in the set CI skips.
#[test]
#[ignore = "large size series: run in release with --ignored, time-boxed"]
fn large_and_deep_inputs_scale_near_linearly_under_every_rule() {
    let _runner = timed();
    assert_series_near_linear(&[
        ("one_line_functions", None, one_line_functions, 256 * 1024),
        (
            "one_line_declarations",
            None,
            one_line_declarations,
            256 * 1024,
        ),
    ]);
}
