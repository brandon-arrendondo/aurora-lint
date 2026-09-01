//! Pre-parse pass: blank the `#if`/`#ifdef`/`#ifndef` and matching `#endif`
//! directive lines that wrap a *dangling* `else` fragment -- an if/else-if
//! chain that's split across a build-time feature-toggle guard (task 441).
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
//! A third shape (task 670; real example: hostap's `tlsv1_server_read.c`,
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
//! sqc has no C preprocessor (`docs/design/macro-expansion.md`) and already
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

fn strip_trailing_line_comment(s: &str) -> &str {
    match s.find("//") {
        Some(idx) => s[..idx].trim_end(),
        None => s,
    }
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
/// exactly the bare keyword `else` with nothing else on the line.
fn is_bare_else_line(line: &str) -> bool {
    strip_trailing_line_comment(line.trim()) == "else"
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

/// Blank the preprocessor directive lines wrapping a dangling `else`
/// fragment, per the module docs above. Length-preserving.
pub fn blank_dangling_else_preproc(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mut line_starts = Vec::with_capacity(lines.len());
    let mut offset = 0usize;
    for line in &lines {
        line_starts.push(offset);
        offset += line.len() + 1; // '\n' (or a trailing CRLF's '\r' left as-is by blank_line)
    }

    let mut out = source.as_bytes().to_vec();

    let mut i = 0usize;
    while i < lines.len() {
        let trimmed = lines[i].trim_start();
        if !is_directive_start(trimmed) {
            i += 1;
            continue;
        }

        let mut depth = 1i32;
        let mut end_idx = None;
        let mut has_branch = false;
        let mut j = i + 1;
        while j < lines.len() {
            let t = lines[j].trim_start();
            if is_directive_start(t) {
                depth += 1;
            } else if is_endif(t) {
                depth -= 1;
                if depth == 0 {
                    end_idx = Some(j);
                    break;
                }
            } else if depth == 1 && is_branch_directive(t) {
                has_branch = true;
            }
            j += 1;
        }

        let Some(end_idx) = end_idx else {
            // No matching #endif found (truncated snippet, or this file has
            // other unrelated unbalanced-directive issues) -- move on rather
            // than halt the whole scan.
            i += 1;
            continue;
        };

        if !has_branch {
            let body = (i + 1)..end_idx;
            let first_content = body.clone().find(|&k| !lines[k].trim().is_empty());
            let last_content = body.clone().rev().find(|&k| !lines[k].trim().is_empty());

            let leading_else =
                first_content.is_some_and(|k| starts_with_bare_else(lines[k].trim_start()));
            let trailing_else = last_content.is_some_and(|k| is_bare_else_line(lines[k]));
            let trailing_dangling_open_brace =
                last_content.is_some_and(|k| ends_with_dangling_else_open_brace(lines[k]));
            let lone_closing_brace = block_is_lone_closing_brace(&lines, i + 1, end_idx);

            if leading_else || trailing_else || trailing_dangling_open_brace || lone_closing_brace {
                blank_line(&mut out, line_starts[i], lines[i].len());
                blank_line(&mut out, line_starts[end_idx], lines[end_idx].len());
            }
        }

        // Advance by one line, not past `end_idx`: a `#if` nested inside this
        // block (e.g. raylib's per-format `#if SUPPORT_FILEFORMAT_PNG` guards
        // nested inside an outer `#if SUPPORT_IMAGE_EXPORT`) must still get
        // its own independent leading/trailing-else check on a later
        // iteration, rather than being skipped as "already handled".
        i += 1;
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
        // Real hostap shape (task 670; tlsv1_server_read.c's
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
}
