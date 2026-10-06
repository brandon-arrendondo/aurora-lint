//! Char-boundary-safe slicing for source text.
//!
//! The scanner also reads code that does not compile, so a multibyte
//! character (UTF-8 identifier, comment, string, a stray `€` where a token
//! should be) can sit at any byte position, including the one a fixed
//! `[..N]` cut lands on. Slicing a `str` inside a character panics, and one
//! panic ends the whole scan. These helpers assume nothing about where
//! non-ASCII text appears: every cut they make is moved to a boundary first.

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

#[cfg(test)]
mod tests {
    use super::*;

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
