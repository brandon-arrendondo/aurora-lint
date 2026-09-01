//! Pre-parse pass: blank a `#if`/`#ifdef`/`#ifndef` + matching `#endif` pair
//! when it opens *immediately* after a goto-style label (task 647).
//!
//! Real shape (hostap `eloop.c`, `eloop_run`):
//! ```c
//! out:
//! #ifdef CONFIG_ELOOP_SELECT
//!     os_free(rfds);
//!     os_free(wfds);
//!     os_free(efds);
//! #endif
//!     return;
//! ```
//!
//! `tree-sitter-c`'s grammar requires a `labeled_statement` (`label ':'
//! statement`) to be followed by exactly one `statement`/`declaration` --
//! unlike a `compound_statement`'s body (`repeat($._block_item)`, where
//! `preproc_ifdef` is itself a valid block item), there is no alternative
//! that lets a bare `#ifdef` sit in that single required slot. GLR error
//! recovery doesn't cleanly isolate the directive into a small `ERROR` node;
//! confirmed via a direct AST dump on the shape above, it instead:
//!
//!  1. Misparses the *first* guarded statement as a bogus `declaration`
//!     (its call target's argument becomes a `type_identifier`, never an
//!     `identifier` node at all) -- invisible to any AST walk keyed on node
//!     kind `"identifier"` (e.g. EXP33-C's read-site scan).
//!  2. Re-parses every *subsequent* statement in the same guarded block as
//!     an ordinary top-level statement with no enclosing `preproc_ifdef`
//!     ancestor at all, even though the source clearly shows it inside the
//!     guard -- silently defeating any analysis keyed on "is this inside
//!     `#ifdef X`" (e.g. EXP33-C's `enclosing_ifdef_guard_key`/
//!     `all_write_sites_ifdef_correlated`, task 590).
//!
//! `case`/`default` labels do NOT have this problem: `case_statement`'s body
//! is `repeat(...)` (zero-or-more), so it can simply match zero statements
//! and cede the `#ifdef` back to the enclosing `compound_statement`, which
//! *does* have a preprocessor-conditional alternative. Only a bare
//! `label:` (`labeled_statement`, mandatory single-statement body) is
//! affected, so this pass only ever touches those.
//!
//! Fix, mirroring `preproc_dangling_else`: blank the opening directive line
//! and its matching `#endif` (same-length whitespace, newlines preserved),
//! so the previously-guarded statements rejoin the enclosing block as
//! ordinary sequential C -- which is also the correct *execution* semantics
//! for a label's non-first statements (a label only ever labels the single
//! statement immediately after it; anything past that already runs
//! unconditionally once control reaches it, guard or not). The cost is the
//! same one `preproc_dangling_else` accepts: this narrow shape loses sqc's
//! usual "maybe compiled" `#ifdef` branch modeling (`process_preproc_conditional`
//! in `analyze::cfg`) in exchange for the guarded statements being visible
//! to analysis at all.
//!
//! Deliberately conservative: skips any block containing its own nested
//! `#else`/`#elif` at the top depth -- unclear how to preserve two-branch
//! semantics while still fitting the single-statement slot, and no
//! confirmed real-world instance needs it (same call `preproc_dangling_else`
//! makes for the analogous case).

fn is_directive_start(trimmed: &str) -> bool {
    trimmed.starts_with("#if") // covers #if, #ifdef, #ifndef (all start "#if")
}

fn is_endif(trimmed: &str) -> bool {
    trimmed.starts_with("#endif")
}

fn is_branch_directive(trimmed: &str) -> bool {
    trimmed.starts_with("#else") || trimmed.starts_with("#elif")
}

/// True if `line`, trimmed, is exactly `identifier:` -- a goto-style label
/// alone on its own line -- and that identifier isn't the `default` keyword
/// (a `default:` case label doesn't have this bug; see module docs).
fn is_bare_label_line(line: &str) -> bool {
    let trimmed = line.trim();
    let Some(name) = trimmed.strip_suffix(':') else {
        return false;
    };
    if name.is_empty() || name == "default" {
        return false;
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
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

/// Blank the `#if`/`#ifdef`/`#ifndef` + matching `#endif` directive lines
/// that open immediately after a bare goto-label line, per the module docs
/// above. Length-preserving.
pub fn blank_label_guarded_preproc(source: &str) -> String {
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

        let prev_content = (0..i).rev().find(|&k| !lines[k].trim().is_empty());
        let follows_label = prev_content.is_some_and(|k| is_bare_label_line(lines[k]));

        if !follows_label {
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
            // No matching #endif found -- move on rather than halt the scan.
            i += 1;
            continue;
        };

        if !has_branch {
            blank_line(&mut out, line_starts[i], lines[i].len());
            blank_line(&mut out, line_starts[end_idx], lines[end_idx].len());
        }

        i += 1;
    }

    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::c_language;

    fn parses_clean(src: &str) -> bool {
        let fixed = blank_label_guarded_preproc(src);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&c_language()).unwrap();
        let tree = parser.parse(&fixed, None).unwrap();
        !tree.root_node().has_error()
    }

    #[test]
    fn fixes_label_immediately_followed_by_ifdef() {
        let src = "\
void f(void) {
    goto out;
out:
#ifdef X
    os_free(rfds);
    os_free(wfds);
    os_free(efds);
#endif
    return;
}
";
        assert!(parses_clean(src));
    }

    #[test]
    fn preserves_byte_length_and_line_count() {
        let src = "\
void f(void) {
    goto out;
out:
#ifdef X
    os_free(rfds);
#endif
    return;
}
";
        let fixed = blank_label_guarded_preproc(src);
        assert_eq!(fixed.len(), src.len());
        assert_eq!(fixed.matches('\n').count(), src.matches('\n').count());
        let pos_orig = src.find("return;").unwrap();
        let pos_fixed = fixed.find("return;").unwrap();
        assert_eq!(pos_orig, pos_fixed);
    }

    #[test]
    fn every_statement_visible_as_identifier_after_fix() {
        // The actual bug symptom: before the fix, os_free(rfds)'s argument
        // parses as a type_identifier (inside a bogus declaration) and
        // os_free(wfds)/os_free(efds) sit outside any preproc_ifdef ancestor.
        let src = "\
void f(void) {
    goto out;
out:
#ifdef X
    os_free(rfds);
    os_free(wfds);
    os_free(efds);
#endif
    return;
}
";
        let fixed = blank_label_guarded_preproc(src);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&c_language()).unwrap();
        let tree = parser.parse(&fixed, None).unwrap();
        assert!(!tree.root_node().has_error());

        let mut cursor = tree.root_node().walk();
        let mut found_ifdef = false;
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "preproc_ifdef" {
                found_ifdef = true;
            }
            for child in node.children(&mut cursor) {
                stack.push(child);
            }
        }
        // The directive lines were blanked -- no preproc_ifdef node should
        // remain (the statements are now ordinary sequential statements).
        assert!(!found_ifdef);
    }

    #[test]
    fn leaves_ordinary_ifdef_block_untouched() {
        // Not immediately after a label -- normal shape, must be a no-op.
        let src = "\
int f(void) {
    int x = 0;
#ifdef DEBUG_MODE
    x = 1;
#endif
    return x;
}
";
        assert_eq!(blank_label_guarded_preproc(src), src);
    }

    #[test]
    fn leaves_default_case_label_untouched() {
        // `default:` is a case_statement (repeat body), not a
        // labeled_statement -- doesn't have this bug, out of scope.
        let src = "\
int f(int x) {
    switch (x) {
    default:
#ifdef Y
        return 1;
#endif
        return 0;
    }
}
";
        assert_eq!(blank_label_guarded_preproc(src), src);
    }

    #[test]
    fn skips_block_with_its_own_else_branch() {
        let src = "\
void f(void) {
    goto out;
out:
#ifdef X
    os_free(rfds);
#else
    noop();
#endif
    return;
}
";
        assert_eq!(blank_label_guarded_preproc(src), src);
    }

    #[test]
    fn leaves_label_followed_by_real_statement_untouched() {
        let src = "\
void f(void) {
    goto out;
out:
    return;
}
";
        assert_eq!(blank_label_guarded_preproc(src), src);
    }
}
