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
//! crash, step-limit or time-limit failure. A file refused by the input guard
//! (not source text) is allowed only for the cases built to be refused.
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
//! `target/robustness-failures/` with the recipe that built it.
//!
//! The suite raises confidence and catches regressions. It cannot show that
//! no input crashes or hangs the scan, and nothing should claim it does.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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

/// How long one scan may take, wall clock, before the test calls it a hang.
/// Far above what any case here takes; the scan's own `--rule-time-limit`
/// fires first for a single runaway rule.
const SCAN_WALL_LIMIT: Duration = Duration::from_secs(900);

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

/// The fixed table: every malformation the task names, on the base files.
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
}

/// How a scan ended.
#[derive(PartialEq, Eq)]
enum End {
    /// It exited with this code.
    Exited(i32),
    /// A signal ended it: a stack overflow aborts the process (SIGABRT)
    /// before containment can see it.
    Signalled(String),
    /// It ran past [`SCAN_WALL_LIMIT`] and the test killed it.
    TimedOut,
}

/// The all-rules manifest as the scan can read it: copied next to the cases,
/// since a Windows binary cannot open a WSL path.
fn manifest_arg(dir: &Path) -> &'static str {
    std::fs::copy(all_rules_manifest(), dir.join("rules-all.toml")).unwrap();
    "rules-all.toml"
}

/// Scan `dir` with every rule, killing the scan at [`SCAN_WALL_LIMIT`].
fn scan_dir(dir: &Path) -> Scan {
    let started = Instant::now();
    // The scan runs from inside the directory and scans `.`: from inside a
    // git checkout (this repository) it would analyse that repository, and
    // a relative path is one a Windows binary run through WSL can resolve.
    let mut child = Command::new(aurora_lint_bin())
        .current_dir(dir)
        .arg(".")
        .arg("-m")
        .arg(manifest_arg(dir))
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
    let end = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break match status.code() {
                Some(code) => End::Exited(code),
                None => End::Signalled(status.to_string()),
            };
        }
        if started.elapsed() > SCAN_WALL_LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            break End::TimedOut;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Scan {
        end,
        stderr: reader.join().unwrap(),
        elapsed: started.elapsed(),
    }
}

/// The failure lines ADR-0017's containment prints for a crash or a runaway:
/// `rule failure (crashed): ...`, `file failure (step limit): ...`, and so on.
fn is_bug_line(line: &str) -> bool {
    let line = line.trim_start_matches("Error: ");
    // The watchdog's line for a unit of work that never reaches a
    // checkpoint: it ends the whole scan.
    if line.starts_with("hang: ") {
        return true;
    }
    ["rule failure (", "file failure (", "prescan failure ("]
        .iter()
        .any(|p| line.starts_with(p))
        && ["(crashed)", "(step limit)", "(time limit)"]
            .iter()
            .any(|c| line.contains(c))
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
    let keep = repo().join("target/robustness-failures").join(label);
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
/// the case and recipe behind each, and how to reproduce the run.
fn assert_scans_cleanly(label: &str, cases: &[Case], how: &str) {
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
    let scan = scan_dir(dir.path());

    let mut problems: Vec<String> = Vec::new();
    let mut failed: Vec<&Case> = Vec::new();
    match &scan.end {
        End::TimedOut => problems.push(format!(
            "the scan did not finish within {SCAN_WALL_LIMIT:?} and was killed"
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
    for line in scan.stderr.lines() {
        let case = case_named(cases, line);
        if is_bug_line(line) {
            problems.push(line.to_string());
            failed.extend(case);
        } else if line.contains("input skipped (") && case.is_none_or(|c| c.refuse == Refuse::Never)
        {
            problems.push(format!("refused a source file: {line}"));
            failed.extend(case);
        }
    }
    for c in cases.iter().filter(|c| c.refuse == Refuse::Must) {
        if !scan.stderr.lines().any(|l| {
            l.contains("input skipped (") && case_named(cases, l).is_some_and(|x| x.name == c.name)
        }) {
            problems.push(format!("{} ({}) was not refused", c.name, c.recipe));
        }
    }
    // Exit 3 is right only when the one thing incomplete is a refused file.
    if scan.end == End::Exited(3) && problems.is_empty() && !scan.stderr.contains("input skipped (")
    {
        problems.push("exit 3 with no failure line".into());
    }
    if problems.is_empty() {
        return;
    }
    failed.sort_by(|a, b| a.name.cmp(&b.name));
    failed.dedup_by(|a, b| a.name == b.name);
    let keep = keep_failures(label, &failed);
    let mut msg = format!(
        "\n{} problem(s) scanning {} {label} case(s) ({how}; {:.1?}):\n",
        problems.len(),
        cases.len(),
        scan.elapsed
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
    if !failed.is_empty() || !matches!(scan.end, End::Exited(_)) {
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
    let seed = env_or("AURORA_LINT_ROBUSTNESS_SEED", DEFAULT_SEED);
    let cases = table_cases(&mut Rng(seed));
    assert_scans_cleanly(
        "table",
        &cases,
        &format!("AURORA_LINT_ROBUSTNESS_SEED={seed}"),
    );
}

#[test]
fn mutated_rule_fixtures_scan_without_a_crash() {
    let seed = env_or("AURORA_LINT_ROBUSTNESS_SEED", DEFAULT_SEED);
    let count = env_or("AURORA_LINT_ROBUSTNESS_MUTANTS", DEFAULT_MUTANTS);
    // A different stream from the table's, so the two never share choices.
    let cases = mutant_cases(&mut Rng(seed ^ 0x6d75_7461_6e74), count);
    assert_scans_cleanly(
        "mutants",
        &cases,
        &format!("AURORA_LINT_ROBUSTNESS_SEED={seed} AURORA_LINT_ROBUSTNESS_MUTANTS={count}"),
    );
}

/// Every rule's fixtures, scanned together under the FULL rule set. A rule's
/// own fixture tests run that rule alone on its own fixtures, which never
/// showed one rule crashing on another rule's fixtures, nor what only a
/// many-file scan reaches (the cross-file prescan, the worker pool).
///
/// About ten minutes in a debug build, so it runs in CI's release
/// robustness job rather than in every `cargo test`.
#[test]
#[ignore = "every fixture under every rule: run in release with --ignored (CI robustness job)"]
fn every_rule_fixture_scans_under_every_rule() {
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
    assert_scans_cleanly("fixtures", &cases, "every rule fixture");
}

/// Inputs too large or too deep for every `cargo test`: generated at test
/// time, never committed. Each must be refused with a reason or analysed
/// within budget -- never a crash, a hang or a stack overflow, which aborts
/// the scan before containment can see it. Run in release, time-boxed:
/// `cargo test --release --test robustness -- --ignored`.
fn large_cases() -> Vec<Case> {
    let mut rng = Rng(DEFAULT_SEED);
    let mut out = Vec::new();
    let mut add = |name: &str, bytes: Vec<u8>, refuse: Refuse| {
        let mut c = Case::new(format!("l_{name}.c"), bytes, format!("large: {name}"));
        c.refuse = refuse;
        out.push(c);
    };
    let limit = 64 * 1024 * 1024; // the default --max-file-size
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
    for depth in [1_000, 10_000, 100_000, 1_000_000] {
        add(
            &format!("braces_{depth}_deep"),
            format!("void h(void) {}{}\n", "{".repeat(depth), "}".repeat(depth)).into_bytes(),
            Refuse::May,
        );
        add(
            &format!("parens_{depth}_deep"),
            format!("int y = {}1{};\n", "(".repeat(depth), ")".repeat(depth)).into_bytes(),
            Refuse::May,
        );
        add(
            &format!("binary_chain_{depth}_long"),
            format!("int x = {}1;\n", "1 + ".repeat(depth)).into_bytes(),
            Refuse::May,
        );
        add(
            &format!("else_if_{depth}_long"),
            format!(
                "int g(int a) {{ if (a == 0) return 0;{} return -1; }}\n",
                (1..depth)
                    .map(|i| format!(" else if (a == {i}) return {i};"))
                    .collect::<String>()
            )
            .into_bytes(),
            Refuse::May,
        );
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
    out
}

#[test]
#[ignore = "large and deep generated inputs: run in release with --ignored, time-boxed"]
fn large_and_deep_inputs_are_refused_or_analysed_within_budget() {
    // One scan per case: a stack overflow aborts the whole process, and in a
    // shared scan it would hide every case after it.
    let cases = large_cases();
    let mut failures = Vec::new();
    for c in cases {
        let name = c.name.clone();
        let result = std::panic::catch_unwind(|| {
            assert_scans_cleanly("large", std::slice::from_ref(&c), "large case")
        });
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
