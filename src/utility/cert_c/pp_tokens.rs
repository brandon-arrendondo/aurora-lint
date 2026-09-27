//! Preprocessing tokens of a `#define` replacement list (C11 6.4, 6.10.3).
//!
//! A rule asking a question of a macro body — how often a parameter is
//! evaluated, whether an operator sits outside parentheses, which number
//! literals it holds — must not read a string or character literal, or a
//! comment, as code: `#define MSG "a + b"` has no `+` operator, `"x=%d"`
//! does not mention the parameter `x`, and a `//` inside `"http://"` starts
//! no comment. [`lex_replacement_list`] splits the body into the tokens the
//! preprocessor sees, and marks on each one what a text scan cannot tell:
//! its bracket depth, whether it is a literal, whether it is an operand of
//! `#` or `##` (so reaches the expansion unexpanded, C11 6.10.3.1), and
//! whether it sits in an operand C11 never evaluates (`sizeof`, `_Alignof`,
//! `typeof`, a `_Generic` controlling expression).
//!
//! tree-sitter's `preproc_arg` stops at the first `/*`, even one inside a
//! string literal, so an AST consumer should lex from the start of the
//! `value` node to the end of the directive rather than lex the node's text:
//! the lexer finds that end itself (the first newline neither escaped nor
//! inside a block comment).

/// What kind of preprocessing token (C11 6.4p1) a [`PpToken`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PpKind {
    /// An identifier, keywords included (the preprocessor has none).
    Identifier,
    /// A preprocessing number (6.4.8): `0644`, `0xffffffffull`, `1e+5`.
    Number,
    /// A string literal, encoding prefix included (`L"…"`, `u8"…"`).
    StringLiteral,
    /// A character constant, encoding prefix included (`'a'`, `L'\0'`).
    CharLiteral,
    /// A punctuator (6.4.6), longest match first: `<<=`, `->`, `##`.
    Punctuator,
    /// Any other single non-white-space character (a stray `\`, `@`, `` ` ``).
    Other,
}

/// One preprocessing token of a replacement list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PpToken<'a> {
    /// What kind of token it is.
    pub kind: PpKind,
    /// The token's spelling, exactly as written.
    pub text: &'a str,
    /// Byte offset of the token in the text given to the lexer.
    pub start: usize,
    /// How many `(`, `[` and `{` enclose the token. An opening bracket
    /// carries the depth outside it, as does its matching close.
    pub depth: usize,
    /// The operand of a `#` (function-like macros only): stringized.
    pub stringized: bool,
    /// An operand of a `##`: pasted as written.
    pub pasted: bool,
    /// Inside an operand C11 does not evaluate: that of `sizeof`,
    /// `_Alignof` or `typeof` (and their GNU spellings), or the controlling
    /// expression of `_Generic`.
    pub unevaluated: bool,
}

impl PpToken<'_> {
    /// Whether this is the punctuator spelled `p` (digraphs normalized:
    /// `%:` is `#`, `<:` is `[`, and so on).
    pub fn is(&self, p: &str) -> bool {
        self.kind == PpKind::Punctuator && normalize_digraph(self.text) == p
    }

    /// Whether this is a string or character literal.
    pub fn is_literal(&self) -> bool {
        matches!(self.kind, PpKind::StringLiteral | PpKind::CharLiteral)
    }

    /// Whether this token is the macro parameter `name` used plainly: an
    /// identifier spelled `name` that is neither stringized nor pasted, so it
    /// is replaced by the fully macro-expanded argument (C11 6.10.3.1).
    pub fn is_plain_use_of(&self, name: &str) -> bool {
        self.kind == PpKind::Identifier && self.text == name && !self.stringized && !self.pasted
    }
}

/// Operators whose operand C11 does not evaluate (6.5.3.4p2, and 6.7.2.5 in
/// C23 for `typeof`), with their GNU spellings. A VLA operand of `sizeof`
/// is the one exception, and not worth modelling in a macro body.
pub const UNEVALUATED_OPERATORS: &[&str] = &[
    "sizeof",
    "_Alignof",
    "alignof",
    "__alignof__",
    "__alignof",
    "typeof",
    "__typeof__",
    "__typeof",
    "typeof_unqual",
    "__typeof_unqual__",
];

/// C punctuators (6.4.6), longest first so the first match is the longest.
const PUNCTUATORS: &[&str] = &[
    "%:%:", "...", "<<=", ">>=", "->", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||",
    "*=", "/=", "%=", "+=", "-=", "&=", "^=", "|=", "##", "<:", ":>", "<%", "%>", "%:", "[", "]",
    "(", ")", "{", "}", ".", "&", "*", "+", "-", "~", "!", "/", "%", "<", ">", "^", "|", "?", ":",
    ";", "=", ",", "#",
];

fn normalize_digraph(p: &str) -> &str {
    match p {
        "%:%:" => "##",
        "%:" => "#",
        "<:" => "[",
        ":>" => "]",
        "<%" => "{",
        "%>" => "}",
        other => other,
    }
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b'$' || b >= 0x80
}

fn is_ident_continue(b: u8) -> bool {
    is_ident_start(b) || b.is_ascii_digit()
}

/// Lex `text`, which starts at (or before) a replacement list, into
/// preprocessing tokens, stopping at the end of the directive: the first
/// newline that is neither escaped by a `\` nor inside a block comment.
/// Comments and line continuations are skipped. `function_like` says
/// whether a `#` is the stringizing operator (6.10.3.2: only in a
/// function-like macro); `##` pastes in either kind.
pub fn lex_replacement_list(text: &str, function_like: bool) -> Vec<PpToken<'_>> {
    let mut tokens = lex(text);
    mark_depth(&mut tokens);
    mark_operands(&mut tokens, function_like);
    mark_unevaluated(&mut tokens);
    tokens
}

/// Byte offset one past the end of the directive whose replacement list
/// `text` starts in, as [`lex_replacement_list`] decides it: at the first
/// newline neither escaped nor inside a block comment (or the text's end).
pub fn directive_end(text: &str) -> usize {
    let mut end = text.len();
    scan(
        text,
        &mut |_: PpKind, _: std::ops::Range<usize>| {},
        &mut end,
    );
    end
}

/// `text` up to the end of its directive (see [`directive_end`]), with
/// every comment and every literal's contents blanked to spaces: the same
/// byte length and line breaks, so an offset in the result is an offset in
/// `text`, but a text scan of it cannot see an operator, a parenthesis or a
/// parameter name inside `"a + b"`, `')'` or `/* x */`. A literal keeps its
/// encoding prefix and quotes.
pub fn mask_literals_and_comments(text: &str) -> String {
    let end = directive_end(text);
    let mut out: Vec<u8> = text.as_bytes()[..end]
        .iter()
        .map(|&b| if b == b'\n' { b'\n' } else { b' ' })
        .collect();
    for t in lex(&text[..end]) {
        let bytes = t.text.as_bytes();
        let range = t.start..t.start + bytes.len();
        if t.is_literal() {
            let open = bytes
                .iter()
                .position(|&b| b == b'"' || b == b'\'')
                .unwrap_or(0);
            out[t.start..=t.start + open].copy_from_slice(&bytes[..=open]);
            let last = bytes.len() - 1;
            if last > open && bytes[last] == bytes[open] {
                out[t.start + last] = bytes[last];
            }
        } else {
            out[range].copy_from_slice(bytes);
        }
    }
    // Only ASCII bytes were written over whole characters, so this holds.
    String::from_utf8(out).expect("masking keeps UTF-8")
}

/// A `#define` directive split into its parts, each read the way the
/// preprocessor reads it: comments are white space wherever they sit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefineDirective<'a> {
    /// The macro's name.
    pub name: &'a str,
    /// The parameter list of a function-like macro, `None` for an
    /// object-like one. A variadic parameter is spelled `...`, or `args...`
    /// for GNU's named form.
    pub params: Option<Vec<String>>,
    /// Byte offset of the replacement list in the text parsed.
    pub body_start: usize,
    /// The replacement list, up to the end of the directive; empty when
    /// the macro expands to nothing.
    pub body: &'a str,
}

impl DefineDirective<'_> {
    /// The replacement list's tokens.
    pub fn tokens(&self) -> Vec<PpToken<'_>> {
        lex_replacement_list(self.body, self.params.is_some())
    }
}

/// Parse the `#define` directive `text` starts with (at its `#`). A macro
/// is function-like only when a `(` follows its name with no white space
/// between them (C11 6.10.3p3).
pub fn parse_define_directive(text: &str) -> Option<DefineDirective<'_>> {
    let end = directive_end(text);
    let tokens = lex(&text[..end]);
    let mut it = tokens.iter().enumerate();
    let (_, hash) = it.next()?;
    let (_, keyword) = it.next()?;
    let (_, name) = it.next()?;
    if !hash.is("#") || keyword.text != "define" || name.kind != PpKind::Identifier {
        return None;
    }
    let name_end = name.start + name.text.len();
    let mut next = 3;
    let params = match tokens.get(3) {
        Some(open) if open.is("(") && open.start == name_end => {
            let mut params: Vec<String> = Vec::new();
            let mut k = 4;
            loop {
                let t = tokens.get(k)?;
                if t.is(")") {
                    break;
                }
                if t.is("...") {
                    match params.last_mut() {
                        Some(last) if tokens[k - 1].kind == PpKind::Identifier => {
                            last.push_str("...")
                        }
                        _ => params.push("...".to_string()),
                    }
                } else if t.kind == PpKind::Identifier {
                    params.push(t.text.to_string());
                } else if !t.is(",") {
                    return None;
                }
                k += 1;
            }
            next = k + 1;
            Some(params)
        }
        _ => None,
    };
    let body_start = tokens.get(next).map_or(end, |t| t.start);
    Some(DefineDirective {
        name: name.text,
        params,
        body_start,
        body: &text[body_start..end],
    })
}

/// The `#define` a `preproc_def` or `preproc_function_def` node holds,
/// parsed from the source text at the node rather than from its fields:
/// tree-sitter's `value` stops at the first `/*`, even one inside a string
/// literal, and a comment inside a function-like macro's body can make it
/// misparse the whole directive. `body_start` is a byte offset in `source`.
pub fn define_at<'s>(node: &tree_sitter::Node, source: &'s str) -> Option<DefineDirective<'s>> {
    let start = node.start_byte();
    let mut define = parse_define_directive(source.get(start..)?)?;
    define.body_start += start;
    Some(define)
}

fn lex(text: &str) -> Vec<PpToken<'_>> {
    let mut tokens = Vec::new();
    let mut end = text.len();
    scan(
        text,
        &mut |kind, range: std::ops::Range<usize>| {
            tokens.push(PpToken {
                kind,
                text: &text[range.clone()],
                start: range.start,
                depth: 0,
                stringized: false,
                pasted: false,
                unevaluated: false,
            })
        },
        &mut end,
    );
    tokens
}

/// The lexer proper: report each token's kind and byte range, and set
/// `end` to where the directive ends.
fn scan(text: &str, emit: &mut dyn FnMut(PpKind, std::ops::Range<usize>), end: &mut usize) {
    let b = text.as_bytes();
    let n = b.len();
    let mut i = 0;
    while i < n {
        let c = b[i];
        if c == b'\n' {
            *end = i;
            return;
        }
        if c == b'\\' && continuation_len(b, i) > 0 {
            i += continuation_len(b, i);
            continue;
        }
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if c == b'/' && b.get(i + 1) == Some(&b'*') {
            i = text[i + 2..].find("*/").map_or(n, |k| i + 2 + k + 2);
            continue;
        }
        if c == b'/' && b.get(i + 1) == Some(&b'/') {
            // A `//` comment runs to the end of the line, and a `\` before
            // that newline splices the next line into the comment.
            while i < n && b[i] != b'\n' {
                if b[i] == b'\\' && continuation_len(b, i) > 0 {
                    i += continuation_len(b, i);
                } else {
                    i += 1;
                }
            }
            continue;
        }
        let start = i;
        if c == b'"' || c == b'\'' {
            i = literal_end(b, i);
            let kind = if c == b'"' {
                PpKind::StringLiteral
            } else {
                PpKind::CharLiteral
            };
            emit(kind, start..i);
        } else if c.is_ascii_digit() || (c == b'.' && b.get(i + 1).is_some_and(u8::is_ascii_digit))
        {
            i += 1;
            while i < n {
                let d = b[i];
                if matches!(d, b'e' | b'E' | b'p' | b'P')
                    && matches!(b.get(i + 1), Some(b'+' | b'-'))
                {
                    i += 2;
                } else if is_ident_continue(d) || d == b'.' {
                    i += 1;
                } else if d == b'\'' && b.get(i + 1).is_some_and(|&x| is_ident_continue(x)) {
                    // C23 digit separator.
                    i += 1;
                } else {
                    break;
                }
            }
            emit(PpKind::Number, start..i);
        } else if is_ident_start(c) {
            while i < n && is_ident_continue(b[i]) {
                i += 1;
            }
            let prefix = &text[start..i];
            if matches!(prefix, "L" | "u" | "U" | "u8") && matches!(b.get(i), Some(b'"' | b'\'')) {
                let kind = if b[i] == b'"' {
                    PpKind::StringLiteral
                } else {
                    PpKind::CharLiteral
                };
                i = literal_end(b, i);
                emit(kind, start..i);
            } else {
                emit(PpKind::Identifier, start..i);
            }
        } else if let Some(p) = PUNCTUATORS.iter().find(|p| text[i..].starts_with(**p)) {
            i += p.len();
            emit(PpKind::Punctuator, start..i);
        } else {
            // One whole character, so a slice never splits a UTF-8 sequence.
            i += text[i..].chars().next().map_or(1, char::len_utf8);
            emit(PpKind::Other, start..i);
        }
    }
    *end = n;
}

/// Length of a line continuation starting at the `\` at `i` (`\` then
/// optional trailing blanks then a newline), or 0 when it is not one.
fn continuation_len(b: &[u8], i: usize) -> usize {
    let mut k = i + 1;
    while k < b.len() && (b[k] == b' ' || b[k] == b'\t' || b[k] == b'\r') {
        k += 1;
    }
    if b.get(k) == Some(&b'\n') {
        k + 1 - i
    } else {
        0
    }
}

/// One past the closing quote of the literal whose opening quote is at `i`;
/// an unterminated literal ends at the end of its line.
fn literal_end(b: &[u8], i: usize) -> usize {
    let quote = b[i];
    let mut k = i + 1;
    while k < b.len() {
        match b[k] {
            b'\\' if continuation_len(b, k) > 0 => k += continuation_len(b, k),
            b'\\' => k += 2,
            b'\n' => return k,
            c if c == quote => return k + 1,
            _ => k += 1,
        }
    }
    b.len()
}

fn mark_depth(tokens: &mut [PpToken]) {
    let mut depth = 0usize;
    for t in tokens.iter_mut() {
        let p = if t.kind == PpKind::Punctuator {
            normalize_digraph(t.text)
        } else {
            ""
        };
        if matches!(p, ")" | "]" | "}") {
            depth = depth.saturating_sub(1);
        }
        t.depth = depth;
        if matches!(p, "(" | "[" | "{") {
            depth += 1;
        }
    }
}

fn mark_operands(tokens: &mut [PpToken], function_like: bool) {
    for k in 0..tokens.len() {
        if tokens[k].is("##") {
            if k > 0 {
                tokens[k - 1].pasted = true;
            }
            if let Some(next) = tokens.get_mut(k + 1) {
                next.pasted = true;
            }
        } else if function_like && tokens[k].is("#") {
            if let Some(next) = tokens.get_mut(k + 1) {
                if next.kind == PpKind::Identifier {
                    next.stringized = true;
                }
            }
        }
    }
}

/// The index of the bracket closing the one at `open`, if it is closed.
pub fn matching_close(tokens: &[PpToken], open: usize) -> Option<usize> {
    let depth = tokens.get(open)?.depth;
    tokens
        .iter()
        .enumerate()
        .skip(open + 1)
        .find(|(_, t)| {
            t.depth == depth
                && t.kind == PpKind::Punctuator
                && matches!(normalize_digraph(t.text), ")" | "]" | "}")
        })
        .map(|(k, _)| k)
}

fn mark_unevaluated(tokens: &mut [PpToken]) {
    let mut k = 0;
    while k < tokens.len() {
        let t = &tokens[k];
        if t.kind == PpKind::Identifier && UNEVALUATED_OPERATORS.contains(&t.text) {
            if tokens.get(k + 1).is_some_and(|n| n.is("(")) {
                if let Some(close) = matching_close(tokens, k + 1) {
                    tokens[k + 2..close]
                        .iter_mut()
                        .for_each(|t| t.unevaluated = true);
                }
            } else {
                // `sizeof x`, `sizeof p->len`, `sizeof a[0]`: a unary
                // expression, taken here as a primary and its postfixes.
                let mut j = k + 1;
                while j < tokens.len() && (tokens[j].is("*") || tokens[j].is("&")) {
                    j += 1;
                }
                if j < tokens.len() {
                    tokens[j].unevaluated = true;
                    j += 1;
                }
                loop {
                    if j + 1 < tokens.len() && (tokens[j].is(".") || tokens[j].is("->")) {
                        tokens[j].unevaluated = true;
                        tokens[j + 1].unevaluated = true;
                        j += 2;
                    } else if j < tokens.len() && tokens[j].is("[") {
                        match matching_close(tokens, j) {
                            Some(close) => {
                                tokens[j..=close]
                                    .iter_mut()
                                    .for_each(|t| t.unevaluated = true);
                                j = close + 1;
                            }
                            None => break,
                        }
                    } else {
                        break;
                    }
                }
            }
        } else if t.kind == PpKind::Identifier
            && t.text == "_Generic"
            && tokens.get(k + 1).is_some_and(|n| n.is("("))
        {
            let depth = tokens[k + 1].depth + 1;
            let mut j = k + 2;
            while j < tokens.len()
                && !(tokens[j].depth == depth && tokens[j].is(","))
                && tokens[j].depth >= depth
            {
                tokens[j].unevaluated = true;
                j += 1;
            }
        }
        k += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts<'a>(tokens: &[PpToken<'a>]) -> Vec<&'a str> {
        tokens.iter().map(|t| t.text).collect()
    }

    #[test]
    fn literals_and_comments_are_not_code() {
        let t = lex_replacement_list("f(\"a + b // c\", 'x') /* x + y */ + g // z", false);
        assert_eq!(
            texts(&t),
            ["f", "(", "\"a + b // c\"", ",", "'x'", ")", "+", "g"]
        );
        assert_eq!(t[2].kind, PpKind::StringLiteral);
        assert_eq!(t[4].kind, PpKind::CharLiteral);
        let t = lex_replacement_list(r#"L"w" u8"s" U'c' L"#, false);
        assert_eq!(texts(&t), [r#"L"w""#, r#"u8"s""#, "U'c'", "L"]);
        assert_eq!(
            t.iter().map(|t| t.kind).collect::<Vec<_>>(),
            [
                PpKind::StringLiteral,
                PpKind::StringLiteral,
                PpKind::CharLiteral,
                PpKind::Identifier
            ]
        );
        // An escaped quote stays inside the literal.
        let t = lex_replacement_list(r#""a\"b" x"#, false);
        assert_eq!(texts(&t), [r#""a\"b""#, "x"]);
    }

    #[test]
    fn pp_numbers_keep_suffixes_and_exponent_signs() {
        let t = lex_replacement_list("0xffffffffull 0644 1e+5 0x1p-3 .5f 1'000 3", false);
        assert_eq!(
            texts(&t),
            [
                "0xffffffffull",
                "0644",
                "1e+5",
                "0x1p-3",
                ".5f",
                "1'000",
                "3"
            ]
        );
        assert!(t.iter().all(|t| t.kind == PpKind::Number));
        // `0x10` is one number, not a `0` and an identifier `x10`.
        let t = lex_replacement_list("(x) + 0x10", true);
        assert_eq!(t.iter().filter(|t| t.text == "x").count(), 1);
    }

    #[test]
    fn punctuators_take_the_longest_match() {
        let t = lex_replacement_list("a<<=b->c...d%:%:e", false);
        assert_eq!(
            texts(&t),
            ["a", "<<=", "b", "->", "c", "...", "d", "%:%:", "e"]
        );
        assert!(t[7].is("##"));
        assert!(t[6].pasted && t[8].pasted);
    }

    #[test]
    fn the_directive_ends_at_an_unescaped_newline_outside_comments() {
        let src = "a \\\n + b /* spans\n lines */ + c\nint next;";
        let t = lex_replacement_list(src, false);
        assert_eq!(texts(&t), ["a", "+", "b", "+", "c"]);
        assert_eq!(&src[directive_end(src)..], "\nint next;");
        // A `//` comment continued by a `\` swallows the next line too.
        let src = "x // note \\\n still comment\ny";
        assert_eq!(texts(&lex_replacement_list(src, false)), ["x"]);
    }

    #[test]
    fn masking_blanks_literals_and_comments_in_place() {
        let src = "(a) + f(\"x + )\", ')') /* b + c */ // d\nnext";
        let masked = mask_literals_and_comments(src);
        assert_eq!(masked, "(a) + f(\"     \", ' ')                 ");
        assert_eq!(masked.len(), directive_end(src));
        let masked = mask_literals_and_comments("L\"é\" + u8'x'");
        assert_eq!(masked, "L\"  \" + u8' '");
    }

    #[test]
    fn define_directives_split_into_name_params_and_body() {
        let d = parse_define_directive("#define SUM(a, b) a /* first */ + b // x\nint y;").unwrap();
        assert_eq!(d.name, "SUM");
        assert_eq!(d.params, Some(vec!["a".to_string(), "b".to_string()]));
        assert_eq!(d.body, "a /* first */ + b // x");
        let texts: Vec<&str> = d.tokens().iter().map(|t| t.text).collect();
        assert_eq!(texts, ["a", "+", "b"]);
        // A space before the `(` makes it object-like.
        let d = parse_define_directive("# define PAREN (x)").unwrap();
        assert_eq!(d.params, None);
        assert_eq!(d.body, "(x)");
        let d = parse_define_directive("#define LOG(fmt, args...) f(fmt, ## args)").unwrap();
        assert_eq!(
            d.params,
            Some(vec!["fmt".to_string(), "args...".to_string()])
        );
        let d = parse_define_directive("#define V(...) g(__VA_ARGS__)").unwrap();
        assert_eq!(d.params, Some(vec!["...".to_string()]));
        let d = parse_define_directive("#define EMPTY /* nothing */\n").unwrap();
        assert_eq!(d.body, "");
        assert!(parse_define_directive("#undef X").is_none());
    }

    #[test]
    fn depth_counts_enclosing_brackets() {
        let t = lex_replacement_list("f(a[i], {b})", false);
        let depth: Vec<usize> = t.iter().map(|t| t.depth).collect();
        //                  f  (  a  [  i  ]  ,  {  b  }  )
        assert_eq!(depth, [0, 0, 1, 1, 2, 1, 1, 1, 2, 1, 0]);
        assert_eq!(matching_close(&t, 1), Some(10));
        assert_eq!(matching_close(&t, 3), Some(5));
    }

    #[test]
    fn operands_of_hash_and_hash_hash_are_marked() {
        let t = lex_replacement_list("#x x a##b # y", true);
        assert!(t[1].stringized && !t[1].pasted);
        assert!(t[2].is_plain_use_of("x"));
        assert!(t[3].pasted && t[5].pasted);
        assert!(t[7].stringized);
        // In an object-like macro `#` is an ordinary token.
        let t = lex_replacement_list("# x", false);
        assert!(!t[1].stringized);
    }

    #[test]
    fn unevaluated_operands_are_marked() {
        let t = lex_replacement_list("sizeof(x++) + sizeof p->n[i++] + y", false);
        let unevaluated: Vec<&str> = t.iter().filter(|t| t.unevaluated).map(|t| t.text).collect();
        assert_eq!(
            unevaluated,
            ["x", "++", "p", "->", "n", "[", "i", "++", "]"]
        );
        assert!(!t.last().unwrap().unevaluated);
        let t = lex_replacement_list("_Generic((x), int: f(x), default: g)(x)", true);
        let marked: Vec<(&str, bool)> = t.iter().map(|t| (t.text, t.unevaluated)).collect();
        assert_eq!(&marked[2..5], [("(", true), ("x", true), (")", true)]);
        assert!(marked[9..].iter().all(|(_, u)| !u));
    }
}
