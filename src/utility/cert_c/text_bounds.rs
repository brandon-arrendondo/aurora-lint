//! Char-boundary-safe slicing for source text.
//!
//! The scanner also reads code that does not compile, so a multibyte
//! character (UTF-8 identifier, comment, string, a stray `€` where a token
//! should be) can sit at any byte position, including the one a fixed
//! `[..N]` cut lands on. Slicing a `str` inside a character panics, and one
//! panic ends the whole scan. These helpers assume nothing about where
//! non-ASCII text appears: every cut they make is moved to a boundary first.
//!
//! The same goes for line endings: a file may end its lines with CRLF, and
//! [`lines_with_starts`] gives each line's byte offset counting the `'\r'`.

/// The longest prefix of `s` that is at most `max_bytes` long and ends on a
/// character boundary.
pub fn prefix_at_most(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    &s[..s.floor_char_boundary(max_bytes)]
}

/// The longest suffix of `s` that is at most `max_bytes` long and starts on a
/// character boundary.
pub fn suffix_at_most(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    &s[s.ceil_char_boundary(s.len() - max_bytes)..]
}

/// `s` cut to at most `max_bytes` bytes on a character boundary, with `...`
/// appended when something was cut. For previews in messages.
pub fn preview(s: &str, max_bytes: usize) -> String {
    if s.len() > max_bytes {
        format!("{}...", prefix_at_most(s, max_bytes))
    } else {
        s.to_string()
    }
}

/// The smallest index at or after `index` that is on a character boundary,
/// clamped to `s.len()`. Use it to advance a byte cursor one step without
/// landing inside a character.
pub fn next_boundary(s: &str, index: usize) -> usize {
    s.ceil_char_boundary(index)
}

/// `s[start..end]`, or `None` when the range is reversed, out of bounds or
/// splits a character.
pub fn slice(s: &str, start: usize, end: usize) -> Option<&str> {
    if start > end {
        return None;
    }
    s.get(start..end)
}

/// The lines of `source` exactly as `str::lines` splits them, with the byte
/// offset where each one starts in `source`.
///
/// `str::lines` strips a CRLF ending's `'\r'` along with its `'\n'`, so a
/// running `offset += line.len() + 1` undercounts one byte per CRLF line and
/// an edit at line k's offset lands k bytes early. These offsets count every
/// byte of each ending. A line's text excludes its `'\r'`, so blanking
/// `starts[k]..starts[k] + lines[k].len()` leaves the ending in place. A lone
/// `'\r'` is not a line ending here, as it is not for `str::lines`.
pub fn lines_with_starts(source: &str) -> (Vec<&str>, Vec<usize>) {
    let mut lines = Vec::new();
    let mut starts = Vec::new();
    let mut offset = 0usize;
    for piece in source.split_inclusive('\n') {
        let line = match piece.strip_suffix('\n') {
            Some(body) => body.strip_suffix('\r').unwrap_or(body),
            None => piece,
        };
        lines.push(line);
        starts.push(offset);
        offset += piece.len();
    }
    (lines, starts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_with_starts_splits_like_str_lines() {
        for s in [
            "",
            "a",
            "a\n",
            "a\nb",
            "a\r\nb\r\n",
            "a\r\n\r\nb",
            "a\rb\rc",
            "a\r",
            "\n\n",
            "x\r\ny\nz\r",
        ] {
            let (lines, starts) = lines_with_starts(s);
            assert_eq!(lines, s.lines().collect::<Vec<_>>(), "{s:?}");
            for (line, &start) in lines.iter().zip(&starts) {
                assert_eq!(&s[start..start + line.len()], *line, "{s:?}");
            }
        }
    }

    #[test]
    fn lines_with_starts_counts_each_crlf_byte() {
        let (_, starts) = lines_with_starts("ab\r\ncd\r\nef");
        assert_eq!(starts, [0, 4, 8]);
        let (lines, starts) = lines_with_starts("a\rb\nc");
        assert_eq!(lines, ["a\rb", "c"]);
        assert_eq!(starts, [0, 4]);
    }

    #[test]
    fn prefix_stops_before_a_split_character() {
        assert_eq!(prefix_at_most("aé", 2), "a");
        assert_eq!(prefix_at_most("aé", 3), "aé");
        assert_eq!(prefix_at_most("€", 1), "");
        assert_eq!(prefix_at_most("abc", 10), "abc");
    }

    #[test]
    fn suffix_starts_after_a_split_character() {
        assert_eq!(suffix_at_most("éa", 2), "a");
        assert_eq!(suffix_at_most("éa", 3), "éa");
        assert_eq!(suffix_at_most("abc", 2), "bc");
    }

    #[test]
    fn preview_marks_a_cut() {
        assert_eq!(preview("€€€", 4), "€...");
        assert_eq!(preview("abc", 3), "abc");
    }

    #[test]
    fn next_boundary_moves_forward_only() {
        assert_eq!(next_boundary("é", 1), 2);
        assert_eq!(next_boundary("é", 0), 0);
        assert_eq!(next_boundary("é", 9), 2);
    }

    #[test]
    fn slice_refuses_bad_ranges() {
        assert_eq!(slice("abc", 2, 1), None);
        assert_eq!(slice("aé", 0, 2), None);
        assert_eq!(slice("abc", 1, 9), None);
        assert_eq!(slice("abc", 1, 3), Some("bc"));
    }
}
