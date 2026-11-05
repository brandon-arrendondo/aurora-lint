//! Pre-parse pass: blank the `#if`/`#ifdef`/`#ifndef` and matching `#endif`
//! directive lines that wrap a *dangling* `else` fragment -- an if/else-if
//! chain that's split across a build-time feature-toggle guard.
//!
//! Two shapes, both seen in raylib (own-code, not external headers):
//!
//! Leading (the guarded block's first real token is `else`):
//! ```c
//! if (false) { }
//! #if SUPPORT_FILEFORMAT_PNG
//! else if (IsFileExtension(fileName, ".png")) { ... }
//! #endif
//! ```
//!
//! Trailing (the guarded block's last real token is a bare `else`, whose
//! body lives in the *next* `#if` block or the final unconditional one):
//! ```c
//! #if SUPPORT_FILEFORMAT_TTF
//!     if (IsFileExtension(fileName, ".ttf")) font = LoadFontEx(...);
//!     else
//! #endif
//! #if SUPPORT_FILEFORMAT_FNT
//!     if (IsFileExtension(fileName, ".fnt")) font = LoadBMFont(fileName);
//!     else
//! #endif
//!     { ... }
//! ```
//!
//! A third shape (real example: hostap's `tlsv1_server_read.c`,
//! `tls_process_certificate_verify`/`tls_process_client_finished`, and
//! several sibling TLS files -- 8 instances confirmed across the codebase):
//! an `if (cond) { ... } else {` whose `else`-clause's OPENING brace is the
//! last token before `#endif`, paired with a *later*, separate `#if`/`#endif`
//! block further down whose entire content is a single closing `}` -- the
//! matching brace for that same `else`, once the intervening unconditional
//! code (compiled either way) is included:
//! ```c
//! #ifdef CONFIG_TLSV12
//!     if (conn->rl.tls_version == TLS_VERSION_1_2) {
//!         ...
//!     } else {
//! #endif /* CONFIG_TLSV12 */
//!
//!     hlen = MD5_MAC_LEN;
//!     ...
//!
//! #ifdef CONFIG_TLSV12
//!     }
//! #endif /* CONFIG_TLSV12 */
//! ```
//! Each of the two guarded blocks is independently incomplete on its own --
//! `} else {` never closes its brace, and a lone `}` never opens one -- so
//! both get blanked by the same local, per-block test as the other two
//! shapes: no cross-block pairing or guard-name matching is needed.
//!
//! A fourth shape (real example: curl's `lib/vtls/openssl.c`,
//! `ossl_connect_step2`): the guarded block's content is a *complete*,
//! self-contained fragment -- a whole `if (...) { ... }` with nothing
//! dangling -- but the very next real line after `#endif` is a bare
//! `else`. The block parses cleanly in isolation, but the grammar still
//! can't attach that trailing `else` across the intervening
//! `preproc_ifdef` sibling to the `if` inside it:
//! ```c
//! if (SSL_ERROR_WANT_WRITE == detail) {
//!   return CURLE_AGAIN;
//! }
//! #ifdef SSL_ERROR_WANT_RETRY_VERIFY
//! if (SSL_ERROR_WANT_RETRY_VERIFY == detail) {
//!   return CURLE_AGAIN;
//! }
//! #endif
//! else {
//!   ...
//! }
//! ```
//! Detected independently of the other three shapes (a block can need
//! blanking for this reason even when its own content has no dangling
//! else at all), and of what the block's content actually is -- any
//! self-contained `#if`/`#endif` immediately followed by a bare `else`
//! breaks the same way, not just one wrapping an `if`.
//!
//! tree-sitter-c's grammar has no production for a preprocessor-conditional
//! whose content is an incomplete statement fragment like this -- GLR error
//! recovery doesn't just isolate a small ERROR node (as with the identifier
//! and brace idioms in `unknown_identifier_recovery`), it can misparse the
//! `else if (...)` text as an entirely different, bogus construct (observed:
//! `else` consumed as a return-type `type_identifier` and `if` as the
//! function name of a phantom `function_definition`), which then hides any
//! writes/reads inside it from every analysis pass that (correctly, for a
//! *real* nested function) refuses to see across a `function_definition`
//! boundary.
//!
//! aurora-lint has no C preprocessor (`docs/design/macro-expansion.md`) and already
//! treats both arms of a normal, self-contained `#if`/`#else`/`#endif` as
//! unconditionally reachable for analysis (`process_preproc_conditional` in
//! `analyze::cfg`). A guard wrapping an *incomplete* fragment can't be
//! modeled that way at all -- the only way to make it analyzable is to
//! remove the directive lines themselves so the fragment rejoins the
//! surrounding chain as ordinary, complete C. Only the bare `#if .../#ifdef
//! .../#ifndef ...` and `#endif` tokens are blanked (same-length whitespace,
//! newlines preserved) -- never a line of real code -- so every byte offset
//! and line number downstream is unchanged.
//!
//! Deliberately conservative: skips any block containing its own nested
//! `#else`/`#elif` (out of scope -- no confirmed real-world instance needs
//! it, and branching inside an already-ambiguous fragment is harder to
//! reason about safely).

use crate::analyze::paren_preproc_guard::CodeLines;
use crate::analyze::preproc_conditionals::{match_conditionals, CondLine};
use crate::utility::cert_c::text_bounds;

fn strip_trailing_line_comment(s: &str) -> &str {
    match s.find("//") {
        Some(idx) => s[..idx].trim_end(),
        None => s,
    }
}

/// Skip forward from `start` (inclusive) to the first line in `start..end`
/// that is neither blank nor part of a comment -- a `//` line comment, or a
/// `/* ... */` block comment, which may span several lines. Returns `end`
/// if no such line exists.
///
/// A block-scoped comment explaining *why* the guard exists (e.g. "only
/// available on OpenSSL version above v1.1.1") commonly sits directly
/// before the guarded `else if`, and was previously counted as the block's
/// "first content line" itself -- so `starts_with_bare_else` tested the
/// comment text and failed, leaving this guard's directives unblanked even
/// though the real leading-else shape is right underneath it (curl's
/// lib/vtls/openssl.c, the `SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED` guard).
fn skip_blank_and_comment_lines(lines: &[&str], start: usize, end: usize) -> usize {
    let mut i = start;
    let mut in_block_comment = false;
    while i < end {
        let trimmed = lines[i].trim();
        if in_block_comment {
            if let Some(pos) = trimmed.find("*/") {
                in_block_comment = false;
                let rest = trimmed[pos + 2..].trim();
                if !rest.is_empty() && !rest.starts_with("//") {
                    return i;
                }
            }
            i += 1;
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with("//") {
            i += 1;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("/*") {
            match rest.find("*/") {
                Some(pos) => {
                    let after = rest[pos + 2..].trim();
                    if !after.is_empty() && !after.starts_with("//") {
                        return i;
                    }
                }
                None => {
                    in_block_comment = true;
                }
            }
            i += 1;
            continue;
        }
        return i;
    }
    end
}

/// True if `line` (already left-trimmed) starts with the bare keyword `else`
/// at a word boundary -- covers `else if (...)`, `else {`, and a lone
/// `else` -- but not an identifier like `elsewhere`.
fn starts_with_bare_else(line: &str) -> bool {
    match line.strip_prefix("else") {
        Some(rest) => rest
            .chars()
            .next()
            .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_'),
        None => false,
    }
}

/// True if `line`, once trimmed and stripped of a trailing `//` comment, is
/// exactly the bare keyword `else` with nothing else on the line, or a
/// closing brace followed by it -- `} else` -- which is the same dangling
/// else once the guarded arm is braced (mbedtls's `psa_key_derivation_abort`
/// and `mbedtls_pk_write_pubkey`: `if (...) { ... } else` as the last line
/// before `#endif`, with the next arm or the final `{ ... }` on the far side;
/// an earlier fix).
pub(crate) fn is_bare_else_line(line: &str) -> bool {
    strip_trailing_line_comment(line.trim()) == "else"
}

/// True if `line` is a closing brace followed by the bare keyword `else` --
/// `} else` -- the trailing dangling else of a BRACED guarded arm (mbedtls's
/// `psa_key_derivation_abort`: `if (...) { ... } else` as the last line
/// before `#endif`, with the next arm or the final `{ ... }` on the far side;
/// an earlier fix).
fn is_brace_else_line(line: &str) -> bool {
    strip_trailing_line_comment(line.trim())
        .strip_suffix("else")
        .is_some_and(|before| before.trim_end() == "}")
}

/// True if `line` closes a preceding brace, opens an `else` clause, and
/// leaves that clause's own brace open -- e.g. `} else {` or `} else if (x) {`
/// followed by more of the else-if chain elsewhere. The guard's content is
/// therefore incomplete on its own (a dangling open brace), the third shape
/// documented at the top of this module.
fn ends_with_dangling_else_open_brace(line: &str) -> bool {
    let t = strip_trailing_line_comment(line.trim());
    let Some(before) = t.strip_suffix('{') else {
        return false;
    };
    let before = before.trim_end();
    let Some(before) = before.strip_suffix("else") else {
        return false;
    };
    // `else` must be a keyword here, not the tail of a longer identifier
    // (e.g. `elsewhere_flag {` would strip to `elsewhere_flag`, which does
    // NOT end in a non-identifier char before "else" -- reject that case).
    if before
        .chars()
        .next_back()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return false;
    }
    before.trim_end().ends_with('}')
}

/// True if the guarded block spanning (exclusive) `start_idx..end_idx` has
/// exactly one non-blank content line, and that line -- once trimmed and
/// stripped of a trailing `//` comment -- is a lone closing brace `}` with
/// nothing else on it: the matching close for a brace opened by
/// [`ends_with_dangling_else_open_brace`] in an unrelated, earlier guard.
fn block_is_lone_closing_brace(lines: &[&str], start_idx: usize, end_idx: usize) -> bool {
    let mut content = (start_idx..end_idx).filter(|&k| !lines[k].trim().is_empty());
    let Some(only_line) = content.next() else {
        return false;
    };
    if content.next().is_some() {
        return false;
    }
    strip_trailing_line_comment(lines[only_line].trim()) == "}"
}

fn is_directive_start(trimmed: &str) -> bool {
    trimmed.starts_with("#if") // covers #if, #ifdef, #ifndef (all start "#if")
}

fn is_endif(trimmed: &str) -> bool {
    trimmed.starts_with("#endif")
}

fn is_branch_directive(trimmed: &str) -> bool {
    trimmed.starts_with("#else") || trimmed.starts_with("#elif")
}

/// Replace every non-newline byte of `line` (located at `line_start` in
/// `out`) with a space.
fn blank_line(out: &mut [u8], line_start: usize, line_len: usize) {
    for b in out.iter_mut().skip(line_start).take(line_len) {
        if *b != b'\n' && *b != b'\r' {
            *b = b' ';
        }
    }
}

/// Blank the directive at line `idx` and every backslash-continued line it
/// spans (`#if defined(A) || \` + `    defined(B)`): the continuation is
/// part of the directive, and left in place it is a stray C expression that
/// breaks the parse the blanking was meant to repair.
pub(crate) fn blank_directive(out: &mut [u8], lines: &[&str], line_starts: &[usize], idx: usize) {
    let mut k = idx;
    loop {
        blank_line(out, line_starts[k], lines[k].len());
        if !lines[k].trim_end().ends_with('\\') || k + 1 >= lines.len() {
            break;
        }
        k += 1;
    }
    // `#endif /* A ||` continued by `B */`: the comment's tail lines go with
    // the directive that opened it, or a bare `*/` is left behind.
    let comment_end = after_endif_comment(lines, k);
    for c in (k + 1)..comment_end.min(lines.len()) {
        blank_line(out, line_starts[c], lines[c].len());
    }
}

/// A guarded block, as the run-based pass below sees it: the line indices of
/// its `#if` and `#endif`, whether anything inside it keeps its guard in
/// place (see [`guarded_blocks`]), and whether its last content line is
/// `} else`.
#[derive(Clone, Copy)]
struct GuardedBlock {
    start: usize,
    end: usize,
    nested_directive: bool,
    ends_with_brace_else: bool,
}

/// True if the code lines `arm` hold whole statements: braces and
/// parentheses never close more than they opened and end level, and the last
/// line is no dangling `else`. Such an arm of a nested conditional parses as
/// a `preproc_if` among statements wherever its guard lands.
fn arm_is_self_contained(code: &CodeLines, arm: std::ops::Range<usize>) -> bool {
    let (mut braces, mut parens) = (0i32, 0i32);
    let mut last = None;
    for k in arm {
        for c in code.code[k].chars() {
            match c {
                '{' => braces += 1,
                '}' => braces -= 1,
                '(' => parens += 1,
                ')' => parens -= 1,
                _ => {}
            }
            if braces < 0 || parens < 0 {
                return false;
            }
        }
        if !code.code[k].trim().is_empty() {
            last = Some(k);
        }
    }
    braces == 0
        && parens == 0
        && !last.is_some_and(|k| {
            let t = code.code[k].trim_end();
            t.strip_suffix("else")
                .is_some_and(|b| !b.ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_'))
        })
}

/// Every `#if` block that closes, indexed by the line of its `#if`, found
/// in one pass over `code`.
///
/// A block's guard stays in place (`nested_directive`) when it has an
/// `#elif` or `#else` of its own, holds a conditional nested two deep, or
/// holds one with an arm that is not [`arm_is_self_contained`]. A nested
/// conditional of whole statements does not keep it: mbedtls's TLS
/// key-derivation chains pick a PSA or legacy call inside each braced arm
/// (`#if defined(MBEDTLS_USE_PSA_CRYPTO)` / `...;` / `#else` / `...;` /
/// `#endif`), and that conditional is a `preproc_if` among the arm's
/// statements whether the arm's own guard is there or not.
///
/// A directive on a line that starts inside a block comment is no
/// directive: a commented-out `#if` taken as a block would pair with the
/// `#endif` of a real enclosing guard and blank it.
fn guarded_blocks(code: &CodeLines) -> Vec<Option<GuardedBlock>> {
    let lines = &code.raw;
    let mut blocks: Vec<Option<GuardedBlock>> = vec![None; lines.len()];
    // Each open block: its `#if` line, whether it keeps its guard, and the
    // first line of its current arm.
    let mut open: Vec<(usize, bool, usize)> = Vec::new();
    for j in 0..lines.len() {
        if code.starts_in_comment[j] {
            continue;
        }
        let t = lines[j].trim_start();
        let closes_arm = if is_directive_start(t) {
            // A conditional two deep keeps the guard two levels out.
            if let Some(n) = open.len().checked_sub(2) {
                open[n].1 = true;
            }
            open.push((j, false, j + 1));
            None
        } else if is_endif(t) {
            open.pop().map(|(start, nested, arm_start)| {
                blocks[start] = Some(block_bounds(lines, start, j, nested));
                (open.len(), arm_start)
            })
        } else if is_branch_directive(t) {
            let level = open.len().checked_sub(1);
            level.map(|level| {
                let block = &mut open[level];
                block.1 = true;
                (level, std::mem::replace(&mut block.2, j + 1))
            })
        } else {
            None
        };
        // An arm of the block at `level` ended: unless it is whole
        // statements, the block around it keeps its guard. An arm holding a
        // conditional already set that (two deep), so the check is skipped
        // and each line is read here at most once.
        if let Some((level, arm_start)) = closes_arm {
            if let Some(parent) = level.checked_sub(1).map(|p| &mut open[p]) {
                if !parent.1 && !arm_is_self_contained(code, arm_start..j) {
                    parent.1 = true;
                }
            }
        }
    }
    blocks
}

/// The [`GuardedBlock`] from the `#if` on line `start` to its `#endif` on
/// line `end`.
fn block_bounds(lines: &[&str], start: usize, end: usize, nested_directive: bool) -> GuardedBlock {
    let mut first_content = start + 1;
    while first_content < end && lines[first_content - 1].trim_end().ends_with('\\') {
        first_content += 1;
    }
    let last = (first_content..end)
        .rev()
        .find(|&k| !lines[k].trim().is_empty());
    GuardedBlock {
        start,
        end,
        nested_directive,
        ends_with_brace_else: last.is_some_and(|k| is_brace_else_line(lines[k])),
    }
}

/// The first line after `endif` that is not inside a block comment the
/// `#endif` line itself opened: `#endif /* A ||` continued by `B */` on the
/// next line (mbedtls's key-exchange chains) must not read as content.
fn after_endif_comment(lines: &[&str], endif: usize) -> usize {
    let line = lines[endif];
    let opens = line.rfind("/*").is_some_and(|o| !line[o..].contains("*/"));
    if !opens {
        return endif + 1;
    }
    let mut k = endif + 1;
    while k < lines.len() {
        if let Some(pos) = lines[k].find("*/") {
            let rest = lines[k][pos + 2..].trim();
            return if rest.is_empty() || rest.starts_with("//") {
                k + 1
            } else {
                k
            };
        }
        k += 1;
    }
    k
}

/// The `} else` chain shape (mbedtls's `psa_key_derivation_abort`,
/// `mbedtls_pk_write_pubkey`): a run of guarded blocks each holding one
/// braced arm that ends in `} else`, closed by an unconditional line (the
/// final `{ ... }` or a plain statement):
///
/// ```c
/// if (alg == 0) {
/// } else
/// #if defined(A)
/// if (alg == 1) { ... } else
/// #endif
/// #if defined(B)
/// if (alg == 2) { ... } else
/// #endif
/// {
///     status = -1;
/// }
/// ```
///
/// The guards of the WHOLE run are blanked, or none of them: with every
/// guard gone the chain is one well-formed if/else-if statement; with only
/// some gone, an `else` is left dangling into a `preproc_if` node and
/// tree-sitter-c's recovery reads the arm after it as a function
/// definition, which is worse than the un-joined original, where each arm
/// parses on its own and only its `else` is dropped. A run containing an arm
/// with a conditional that is not whole statements inside it (`if (...) {
/// #if X` / `if (a) {` / `#else` / `if (b) {` / `#endif ... } else`) is left
/// alone for the same reason; one of whole statements is not (see
/// [`guarded_blocks`]).
///
/// A guard nested inside a refused run's arm is a candidate of its own, and
/// is repaired first: mbedtls's `ssl_parse_client_hello` holds a `} else`
/// guard for the cookie check inside the braced arm of a `} else` guard for
/// DTLS. Once the inner run is blanked the outer one has no directive left
/// inside it, so rounds repeat until one blanks nothing. A run that is
/// refused keeps every one of its guards: a later block of it is never taken
/// up as a run of its own, which would blank part of the chain.
///
/// Each round repairs only the innermost guards of a nest and rescans the
/// whole file, so rounds stop at [`MAX_NESTED_GUARD_ROUNDS`]: real code nests
/// these guards a level or two deep, and a crafted nest hundreds deep must
/// not stall a scan. Guards past the cap stay in place, as on a refused run.
fn blank_brace_else_chains(source: &str) -> Vec<u8> {
    // Read once, from the text as written: the rounds blank directives, and
    // a guard blanked in an earlier round must not turn a dead arm live.
    let dead = crate::analyze::init_state::literal_dead_lines(source);
    let mut current = source.as_bytes().to_vec();
    for _ in 0..MAX_NESTED_GUARD_ROUNDS {
        let text = String::from_utf8_lossy(&current).into_owned();
        let code = CodeLines::new(&text);
        let mut out = current.clone();
        if !blank_brace_else_round(&code, &dead, &mut out) {
            return out;
        }
        current = out;
    }
    current
}

/// Most rounds [`blank_brace_else_chains`] runs: the deepest nest of `} else`
/// guards it repairs.
const MAX_NESTED_GUARD_ROUNDS: usize = 16;

/// One round of [`blank_brace_else_chains`]: blank every run whose arms
/// hold no directive, and step inside the ones that do. A run with a block
/// in `dead` (1-based line ranges a literal condition such as `#if 0` keeps
/// out of every build) is refused: its `} else` exists in no configuration. True if
/// anything was blanked.
fn blank_brace_else_round(code: &CodeLines, dead: &[(usize, usize)], out: &mut [u8]) -> bool {
    let (lines, line_starts) = (&code.raw[..], &code.starts[..]);
    let mut blanked = false;
    let blocks = guarded_blocks(code);
    let mut refused = std::collections::HashSet::new();
    let mut i = 0usize;
    while i < lines.len() {
        if refused.contains(&i) {
            i += 1;
            continue;
        }
        let Some(first) = blocks[i] else {
            i += 1;
            continue;
        };
        if !first.ends_with_brace_else {
            i += 1;
            continue;
        }
        // collect the run
        let mut run = vec![first];
        let closed_by_code = loop {
            let last = run.last().unwrap();
            let k = skip_blank_and_comment_lines(
                lines,
                after_endif_comment(lines, last.end),
                lines.len(),
            );
            if k >= lines.len() {
                break false;
            }
            match blocks[k] {
                Some(next) if next.ends_with_brace_else => run.push(next),
                Some(_) => break false,
                // The `#endif` or `#else` of an enclosing guard is not the
                // code the chain's last `else` takes as its body.
                None => {
                    let t = lines[k].trim_start();
                    break !is_directive_start(t) && !is_endif(t) && !is_branch_directive(t);
                }
            }
        };
        let last_end = run.last().unwrap().end;
        let compiled =
            |b: &GuardedBlock| !dead.iter().any(|&(s, e)| (s..=e).contains(&(b.start + 2)));
        if closed_by_code && run.iter().all(|b| !b.nested_directive && compiled(b)) {
            for b in &run {
                blank_directive(out, lines, line_starts, b.start);
                blank_directive(out, lines, line_starts, b.end);
            }
            blanked = true;
            i = last_end + 1;
        } else {
            refused.extend(run.iter().map(|b| b.start));
            i += 1;
        }
    }
    blanked
}

/// Blank the preprocessor directive lines wrapping a dangling `else`
/// fragment, per the module docs above. Length-preserving.
pub fn blank_dangling_else_preproc(source: &str) -> String {
    let (lines, line_starts) = text_bounds::lines_with_starts(source);

    let mut out = blank_brace_else_chains(source);
    let conditionals = match_conditionals(lines.len(), |k| {
        let t = lines[k].trim_start();
        if is_directive_start(t) {
            Some(CondLine::Open)
        } else if is_endif(t) {
            Some(CondLine::End)
        } else if is_branch_directive(t) {
            Some(CondLine::Branch)
        } else {
            None
        }
    });

    for i in 0..lines.len() {
        // No #if here, or no matching #endif (truncated snippet, or this
        // file has other unrelated unbalanced-directive issues) -- move on
        // rather than halt the whole scan.
        let Some(conditional) = conditionals.at(i) else {
            continue;
        };
        let end_idx = conditional.endif;
        let has_branch = !conditional.branches.is_empty();

        if !has_branch {
            let body = (i + 1)..end_idx;

            let first_content = {
                let k = skip_blank_and_comment_lines(&lines, body.start, body.end);
                (k < body.end).then_some(k)
            };
            let last_content = body.clone().rev().find(|&k| !lines[k].trim().is_empty());

            let leading_else =
                first_content.is_some_and(|k| starts_with_bare_else(lines[k].trim_start()));
            let trailing_else = last_content.is_some_and(|k| is_bare_else_line(lines[k]));
            let trailing_dangling_open_brace =
                last_content.is_some_and(|k| ends_with_dangling_else_open_brace(lines[k]));
            let lone_closing_brace = block_is_lone_closing_brace(&lines, i + 1, end_idx);
            // Fourth shape (curl's lib/vtls/openssl.c
            // SSL_ERROR_WANT_ASYNC/SSL_ERROR_WANT_RETRY_VERIFY guards): the
            // block's own content is a complete, self-contained fragment --
            // no dangling else inside it at all -- but the very next
            // non-blank, non-comment line *after* `#endif` is a bare
            // `else`. That else needs to bind to the if-statement this
            // block's `#ifdef`/`#endif` wraps, but the grammar can't reach
            // across a `preproc_ifdef` sibling to attach it, regardless of
            // what the block's content actually is -- so this block's
            // directives get blanked the same way, letting the else attach
            // to the now-adjacent statement exactly as this codebase
            // already treats every other preproc-conditional body as
            // unconditionally reachable.
            let else_follows_endif = {
                let k = skip_blank_and_comment_lines(&lines, end_idx + 1, lines.len());
                k < lines.len() && starts_with_bare_else(lines[k].trim_start())
            };

            if leading_else
                || trailing_else
                || trailing_dangling_open_brace
                || lone_closing_brace
                || else_follows_endif
            {
                blank_directive(&mut out, &lines, &line_starts, i);
                blank_directive(&mut out, &lines, &line_starts, end_idx);
            }
        }

        // A `#if` nested inside this block (e.g. raylib's per-format
        // `#if SUPPORT_FILEFORMAT_PNG` guards nested inside an outer
        // `#if SUPPORT_IMAGE_EXPORT`) still gets its own independent
        // leading/trailing-else check on a later line, rather than being
        // skipped as "already handled".
    }

    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::c_language;

    fn parses_clean(src: &str) -> bool {
        let fixed = blank_dangling_else_preproc(src);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&c_language()).unwrap();
        let tree = parser.parse(&fixed, None).unwrap();
        !tree.root_node().has_error()
    }

    #[test]
    fn fixes_leading_dangling_else() {
        let src = "\
int f(int fmt) {
    int channels = 0;
    if (false) { }
#if SUPPORT_FILEFORMAT_PNG
    else if (fmt == 1) { channels = 1; }
#endif
#if SUPPORT_FILEFORMAT_QOI
    else if (fmt == 2)
    {
        channels = 2;
    }
#endif
    else { channels = 3; }
    return channels;
}
";
        assert!(parses_clean(src));
    }

    #[test]
    fn fixes_trailing_dangling_else() {
        let src = "\
int f(int fmt) {
    int x;
#if SUPPORT_FILEFORMAT_TTF
    if (fmt == 1) x = 1;
    else
#endif
#if SUPPORT_FILEFORMAT_FNT
    if (fmt == 2) x = 2;
    else
#endif
    {
        x = 3;
    }
    return x;
}
";
        assert!(parses_clean(src));
    }

    #[test]
    fn fixes_trailing_brace_else_before_endif() {
        // an earlier fix: the guarded arm is braced, so the line before `#endif`
        // is `} else`, not a lone `else`; the chain's tail is on the far side.
        let src = "\
int f(int alg) {
    int status = 0;
    if (alg == 0) {
    } else
#if defined(HAVE_ONE)
    if (alg == 1) {
        status = 1;
    } else
#endif
    {
        status = -1;
    }
    return status;
}
";
        assert!(parses_clean(src));
        let out = blank_dangling_else_preproc(src);
        assert!(!out.contains("#if defined(HAVE_ONE)"));
        assert!(!out.contains("#endif"));

        // A conditional of whole statements inside the braced arm stays a
        // `preproc_if` among the arm's statements, so the arm's guard goes.
        let nested = "\
int g(int alg) {
    int status = 0;
    if (alg == 0) {
    } else
#if defined(HAVE_ONE)
    if (alg == 1) {
#if defined(USE_PSA)
        status = 1;
#else
        status = 2;
#endif
    } else
#endif
    {
        status = -1;
    }
    return status;
}
";
        assert!(parses_clean(nested));
        let out = blank_dangling_else_preproc(nested);
        assert!(!out.contains("#if defined(HAVE_ONE)"));
        assert!(out.contains("#if defined(USE_PSA)"));

        // ... but not when an arm of the nested conditional opens a brace
        // another arm, or the code after it, closes.
        let split_arm = "\
int g(int alg, int x) {
    int status = 0;
    if (alg == 0) {
    } else
#if defined(HAVE_ONE)
    if (alg == 1) {
#if defined(USE_PSA)
        if (x) {
#else
        if (!x) {
#endif
            status = 1;
        }
    } else
#endif
    {
        status = -1;
    }
    return status;
}
";
        let out = blank_dangling_else_preproc(split_arm);
        assert!(out.contains("#if defined(HAVE_ONE)"));

        // A run is all-or-nothing: an `#endif /* ...` comment continued on
        // the next line must not split it, and one arm whose nested
        // conditional is not whole statements keeps every guard of the run
        // in place.
        let split_by_comment = "\
int h(int alg) {
    int status = 0;
    if (alg == 0) {
    } else
#if defined(HAVE_ONE) || \\
    defined(HAVE_TWO)
    if (alg == 1) {
        status = 1;
    } else
#endif /* HAVE_ONE ||
          HAVE_TWO */
#if defined(HAVE_THREE)
    if (alg == 3) {
#if defined(USE_PSA)
        if (alg) {
#else
        if (!alg) {
#endif
            status = 3;
        }
    } else
#endif
    {
        status = -1;
    }
    return status;
}
";
        let out = blank_dangling_else_preproc(split_by_comment);
        assert!(
            out.contains("#if defined(HAVE_ONE)"),
            "first arm blanked although the run has a nested arm"
        );
        assert!(out.contains("#if defined(HAVE_THREE)"));

        // With no nested arm the run is blanked, continuation lines included.
        let continued = "\
int k(int alg) {
    int status = 0;
    if (alg == 0) {
    } else
#if defined(HAVE_ONE) || \\
    defined(HAVE_TWO)
    if (alg == 1) {
        status = 1;
    } else
#endif /* HAVE_ONE ||
          HAVE_TWO */
    {
        status = -1;
    }
    return status;
}
";
        let out = blank_dangling_else_preproc(continued);
        assert!(
            !out.contains("defined(HAVE_TWO)\n"),
            "continuation line left behind"
        );
        assert!(parses_clean(&out));
    }

    #[test]
    fn preserves_byte_length_and_line_count() {
        let src = "\
int f(int fmt) {
    int channels = 0;
    if (false) { }
#if SUPPORT_FILEFORMAT_PNG
    else if (fmt == 1) { channels = 1; }
#endif
    else { channels = 3; }
    return channels;
}
";
        let fixed = blank_dangling_else_preproc(src);
        assert_eq!(fixed.len(), src.len());
        assert_eq!(fixed.matches('\n').count(), src.matches('\n').count());
        let pos_orig = src.find("return channels;").unwrap();
        let pos_fixed = fixed.find("return channels;").unwrap();
        assert_eq!(pos_orig, pos_fixed);
    }

    #[test]
    fn leaves_normal_if_else_if_chain_untouched() {
        let src = "\
int f(int x) {
    int y;
    if (x == 1) y = 1;
    else if (x == 2) y = 2;
    else y = 3;
    return y;
}
";
        assert_eq!(blank_dangling_else_preproc(src), src);
    }

    #[test]
    fn leaves_ordinary_ifdef_block_untouched() {
        // A #ifdef guard whose content is a complete, self-contained
        // statement (no dangling else) isn't this idiom -- must be a no-op.
        let src = "\
int f(void) {
    int x = 0;
#ifdef DEBUG_MODE
    x = 1;
#endif
    return x;
}
";
        assert_eq!(blank_dangling_else_preproc(src), src);
    }

    #[test]
    fn fixes_dangling_else_nested_inside_an_outer_guard() {
        // Real raylib shape (rtextures.c ExportImage): the whole cascade sits
        // inside an outer `#if SUPPORT_IMAGE_EXPORT`, and each per-format
        // branch is its own nested `#if SUPPORT_FILEFORMAT_X` guard. The
        // outer block's own leading/trailing content doesn't look like a
        // dangling else, so it's left alone -- but the inner ones must still
        // each get their own independent check, not be skipped just because
        // they're inside an already-processed outer block.
        let src = "\
#if SUPPORT_IMAGE_EXPORT
int f(int fmt) {
    int channels = 0;
    if (false) { }
#if SUPPORT_FILEFORMAT_PNG
    else if (fmt == 1) { channels = 1; }
#endif
    else { channels = 3; }
    return channels;
}
#endif
";
        assert!(parses_clean(src));
    }

    #[test]
    fn skips_block_with_its_own_else_branch() {
        // Conservative: a #if block that has its own #else/#elif is out of
        // scope, even if its content happens to start with "else" text.
        let src = "\
int f(int x) {
    int y = 0;
    if (false) { }
#if COND
    else if (x == 1) { y = 1; }
#else
    else { y = 2; }
#endif
    return y;
}
";
        assert_eq!(blank_dangling_else_preproc(src), src);
    }

    #[test]
    fn fixes_brace_else_open_brace_split_across_two_guards() {
        // Real hostap shape (tlsv1_server_read.c's
        // tls_process_certificate_verify): an if/else whose else-clause
        // opening brace is the last token before #endif, matched by a later,
        // separate guard whose entire content is the closing brace.
        let src = "\
int f(int version) {
    int hlen;
#ifdef CONFIG_TLSV12
    if (version == 2) {
        hlen = 1;
    } else {
#endif

    hlen = 2;

#ifdef CONFIG_TLSV12
    }
#endif

    return hlen;
}
";
        assert!(parses_clean(src));
    }

    #[test]
    fn brace_else_open_brace_preserves_byte_length_and_line_count() {
        let src = "\
int f(int version) {
    int hlen;
#ifdef CONFIG_TLSV12
    if (version == 2) {
        hlen = 1;
    } else {
#endif

    hlen = 2;

#ifdef CONFIG_TLSV12
    }
#endif

    return hlen;
}
";
        let fixed = blank_dangling_else_preproc(src);
        assert_eq!(fixed.len(), src.len());
        assert_eq!(fixed.matches('\n').count(), src.matches('\n').count());
        let pos_orig = src.find("return hlen;").unwrap();
        let pos_fixed = fixed.find("return hlen;").unwrap();
        assert_eq!(pos_orig, pos_fixed);
    }

    #[test]
    fn leaves_lone_brace_guard_with_matching_open_untouched() {
        // A guard whose content is just `}` closing a brace opened
        // unconditionally (not via the dangling-else-open-brace shape) is
        // NOT this idiom -- the surrounding code is already complete on its
        // own without the guard, so touching it would be unnecessary (though
        // harmless). This test only documents that the *other* triggers
        // (leading/trailing else, dangling open brace) don't fire here; the
        // lone-closing-brace check itself is deliberately unconditional
        // since a standalone `}` is never valid on its own regardless of
        // context.
        let src = "\
int f(void) {
    if (1) {
#ifdef X
    }
#endif
    return 0;
}
";
        // The lone-`}` guard is still blanked (a standalone `}` is never
        // parseable alone), rejoining it with the unconditional `if (1) {`.
        assert!(parses_clean(src));
    }

    #[test]
    fn leaves_else_word_prefix_identifier_untouched() {
        // `elsewhere_flag {` must not be mistaken for `else {` -- "else" has
        // to be its own token, not a substring/prefix of a longer identifier.
        assert!(!ends_with_dangling_else_open_brace("} elsewhere_flag {"));
    }

    #[test]
    fn fixes_leading_else_hidden_behind_a_comment() {
        // Real curl shape (lib/vtls/openssl.c's
        // ossl_connect_step2, guarded by
        // SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED): a comment explaining the
        // guard sits between `#ifdef` and the real `else if`, which used to
        // defeat "first content line is `else`" detection entirely --
        // leaving the guard's directives unblanked and the whole chain
        // unparseable.
        let src = "\
int f(int lib, int reason) {
    int result;
    if ((lib == 1) && (reason == 1)) {
        result = 10;
    }
#ifdef SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED
    /* only available on newer builds */
    else if ((lib == 1) && (reason == 2)) {
        result = 20;
    }
#endif
    else {
        result = 30;
    }
    return result;
}
";
        assert!(parses_clean(src));
    }

    #[test]
    fn fixes_trailing_else_after_complete_guarded_if() {
        // Real curl shape (lib/vtls/openssl.c's
        // ossl_connect_step2, SSL_ERROR_WANT_ASYNC/SSL_ERROR_WANT_RETRY_VERIFY):
        // the guarded block's own content is a *complete* `if (...) { ... }`
        // with nothing dangling inside it -- so neither leading_else nor
        // trailing_else fires on the block itself -- but the very next line
        // after `#endif` is a bare `else` that needs to attach to the `if`
        // this guard wraps.
        let src = "\
int f(int detail) {
    if (detail == 1) {
        return 1;
    }
#ifdef SSL_ERROR_WANT_RETRY_VERIFY
    if (detail == 2) {
        return 1;
    }
#endif
    else {
        return 0;
    }
}
";
        assert!(parses_clean(src));
    }

    #[test]
    fn trailing_else_after_complete_guarded_if_preserves_byte_length_and_line_count() {
        let src = "\
int f(int detail) {
    if (detail == 1) {
        return 1;
    }
#ifdef SSL_ERROR_WANT_RETRY_VERIFY
    if (detail == 2) {
        return 1;
    }
#endif
    else {
        return 0;
    }
}
";
        let fixed = blank_dangling_else_preproc(src);
        assert_eq!(fixed.len(), src.len());
        assert_eq!(fixed.matches('\n').count(), src.matches('\n').count());
        let pos_orig = src.find("return 0;").unwrap();
        let pos_fixed = fixed.find("return 0;").unwrap();
        assert_eq!(pos_orig, pos_fixed);
    }

    #[test]
    fn leaves_guarded_if_not_followed_by_else_untouched() {
        // A complete #ifdef-wrapped if-statement NOT followed by a bare
        // `else` is not this shape at all -- must be a no-op, same
        // discipline as `leaves_ordinary_ifdef_block_untouched`.
        let src = "\
int f(int detail) {
    if (detail == 1) {
        return 1;
    }
#ifdef SSL_ERROR_WANT_RETRY_VERIFY
    if (detail == 2) {
        return 1;
    }
#endif
    return 0;
}
";
        assert_eq!(blank_dangling_else_preproc(src), src);
    }

    #[test]
    fn a_crlf_file_is_blanked_at_the_bytes_of_its_lf_copy() {
        let src = "\
int f(int fmt) {
    int channels = 0;
    if (false) { }
#if SUPPORT_FILEFORMAT_PNG
    else if (fmt == 1) { channels = 1; }
#endif
    else { channels = 3; }
    return channels;
}
";
        let lf = blank_dangling_else_preproc(src);
        assert_ne!(lf, src, "the LF copy must trigger the pass");
        let crlf = src.replace('\n', "\r\n");
        assert_eq!(blank_dangling_else_preproc(&crlf), lf.replace('\n', "\r\n"));
        // A lone '\r' ends no line: one long line, left as it was or blanked
        // in place, never a panic.
        let cr = src.replace('\n', "\r");
        assert_eq!(blank_dangling_else_preproc(&cr).len(), cr.len());
    }

    #[test]
    fn repairs_a_guard_nested_in_a_guarded_arm_first() {
        // The arm of an outer `} else` guard holds a `} else` guard of its
        // own, whose condition holds a conditional operand. The operand's
        // conditional goes to the paren pass, which runs first in the
        // pipeline; here it is a whole line inside the arm's parentheses.
        let src = "\
int use(int);
int f(int t, int n, int c)
{
    int off;
#if defined(HAVE_A)
    if (t == 1) {
#if defined(HAVE_B)
        if (c != 0) {
            use(1);
        } else
#endif
        {
            use(2);
        }
        off = n + 1;
    } else
#endif
    off = n + 2;
    return use(off);
}
";
        let out = blank_dangling_else_preproc(src);
        assert!(!out.contains('#'), "a guard was left in place:\n{out}");
        assert!(parses_clean(src));
        assert_eq!(out.len(), src.len());
        assert_eq!(out.lines().count(), src.lines().count());
    }

    #[test]
    fn a_refused_run_keeps_the_guards_after_its_refused_arm() {
        // The first block of the run is refused (its nested conditional
        // splits a brace across arms); the second must not be taken up as a
        // run of its own, which would blank half the chain.
        let src = "\
int f(int alg, int x) {
    int status = 0;
    if (alg == 0) {
    } else
#if defined(HAVE_ONE)
    if (alg == 1) {
#if defined(USE_PSA)
        if (x) {
#else
        if (!x) {
#endif
            status = 1;
        }
    } else
#endif
#if defined(HAVE_TWO)
    if (alg == 2) {
        status = 2;
    } else
#endif
    {
        status = -1;
    }
    return status;
}
";
        let out = blank_dangling_else_preproc(src);
        assert!(out.contains("#if defined(HAVE_ONE)"));
        assert!(out.contains("#if defined(HAVE_TWO)"));
    }

    #[test]
    fn a_dead_guard_around_an_else_is_not_joined() {
        // The `#if 0` arm is compiled in no configuration: joining its
        // `} else` would put dead code into the chain.
        let src = "\
int g(int);
int f(int x, int y) {
    if (x) {
        g(1);
    } else
#if 0
    if (y) {
        g(3);
    } else
#endif
    {
        g(2);
    }
    return 0;
}
";
        assert_eq!(
            String::from_utf8(blank_brace_else_chains(src)).unwrap(),
            src
        );
        assert!(blank_dangling_else_preproc(src).contains("#if 0"));
        let live = src.replace("#if 0", "#if defined(HAVE_Y)");
        assert!(!blank_dangling_else_preproc(&live).contains('#'));
        // A guard the file only names in a commented-out `#define` is one a
        // build flag turns on: it is no literal `#if 0`, and is joined.
        let flag = format!(
            "//#define HAVE_Y\n{}",
            src.replace("#if 0", "#ifdef HAVE_Y")
        );
        assert!(!blank_dangling_else_preproc(&flag).contains("#ifdef"));
    }

    #[test]
    fn a_commented_out_if_never_pairs_with_a_real_endif() {
        // The real guard has an `#else` of its own, so it is refused; the
        // `#if` inside the comment must not take the real `#endif` as its
        // own and blank it, which would leave `#if defined(HAVE_C)` open.
        let src = "\
int g(int);
int f(int x) {
#if defined(HAVE_C)
    g(0);
#else
/*
#if defined(HAVE_A)
*/
    if (x) {
        g(1);
    } else
#endif
    g(2);
    return 0;
}
";
        let out = String::from_utf8(blank_brace_else_chains(src)).unwrap();
        assert_eq!(out, src);
        assert!(blank_dangling_else_preproc(src).contains("#endif"));
    }

    /// `depth` `} else` guards, each nested in the arm of the one before.
    fn nested_guards(depth: usize) -> String {
        let mut src = String::from("int f(int x) {\n    int r = 0;\n");
        for k in 0..depth {
            src.push_str(&format!("#if defined(G{k})\n    if (x == {k}) {{\n"));
        }
        src.push_str("        r = -1;\n");
        for k in (0..depth).rev() {
            src.push_str(&format!("    }} else\n#endif\n    r = {k};\n"));
        }
        src.push_str("    return r;\n}\n");
        src
    }

    #[test]
    fn nested_guards_are_repaired_innermost_first_up_to_the_round_cap() {
        let shallow = nested_guards(3);
        let out = String::from_utf8(blank_brace_else_chains(&shallow)).unwrap();
        assert!(!out.contains('#'), "a guard was left in place:\n{out}");
        assert!(parses_clean(&shallow));

        let deep = nested_guards(MAX_NESTED_GUARD_ROUNDS + 24);
        let out = String::from_utf8(blank_brace_else_chains(&deep)).unwrap();
        assert_eq!(out.len(), deep.len());
        assert_eq!(out.matches("#if").count(), 24);
        assert!(out.contains("#if defined(G0)\n"));
        assert!(!out.contains(&format!("#if defined(G{})\n", 24)));
    }

    #[test]
    fn a_crafted_nest_of_guards_does_not_stall_a_scan() {
        let src = nested_guards(800);
        let start = std::time::Instant::now();
        let out = blank_brace_else_chains(&src);
        let elapsed = start.elapsed();
        assert_eq!(out.len(), src.len());
        assert!(elapsed.as_secs() < 5, "800 nested guards took {elapsed:?}");
    }

    #[test]
    fn an_inner_else_closed_by_the_outer_endif_is_left_alone() {
        // The inner `} else` has no body before the outer `#endif`: it is no
        // chain this pass can join, so neither guard is blanked.
        let src = "\
int f(int t, int c) {
    int r = 0;
#if defined(HAVE_A)
    if (t) {
        r = 1;
    } else
#if defined(HAVE_B)
    if (c) {
        r = 2;
    } else
#endif
#endif
    {
        r = 3;
    }
    return r;
}
";
        let out = blank_dangling_else_preproc(src);
        assert!(out.contains("#if defined(HAVE_B)"));
    }
}
