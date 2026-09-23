//! Which vararg slot each conversion specification of a format string
//! consumes, and whether that conversion dereferences the pointer it is
//! handed.
//!
//! Every rule that reasons about a `...` argument needs the same thing first:
//! the mapping from an argument's *position* in the vararg tail to the
//! conversion that will consume it. Without it a check can only treat every
//! tail slot alike, which is how EXP34-C came to report "passing potentially
//! null pointer 'buf' to 'wpa_printf' which does not check for NULL" about a
//! pointer whose slot was a `%p` -- a conversion that prints the pointer
//! value and never dereferences anything.
//!
//! The model is deliberately one-directional in what it will assert: it
//! answers "this slot is dereferenced" only when the whole directive is
//! recognized, and answers [`format_slots::SlotUse::Unknown`] for everything else --
//! including for any index past the last conversion. sqlite's
//! `%T`/`%#T`/`%q`/`%z`/`%w`/`%Q` are the recurring real case:
//! implementation-private conversions whose argument handling is written in
//! the implementation, not in the C standard.
//!
//! An unrecognized conversion makes its OWN slot unknown and no more. The
//! parse continues past it counting one consumed argument, because that is
//! what a conversion specification does in every real implementation -- one
//! `va_arg` in its handler. The genuine zero-argument conversions are `%%`
//! and glibc's `%m`, and both are modelled by name. Stopping instead, on the
//! reasoning that an unknown conversion consumes an unknown count, silenced
//! 36 slots across the pinned corpora whose conversion was a plain `%s` --
//! `"%z%s%s"`, `"DELETE FROM %Q.%s WHERE %s=%Q"`, `"unknown join type:
//! %T%s%T%s%T"`. Those claims would have been true, so declining to make
//! them is narrowing what the rule reports (`docs/adr/0001`) rather than
//! fixing a misfire (`docs/adr/0005`).
//!
//! Each family is read separately, and a family whose syntax the string
//! *violates* abstains instead of reporting nothing-is-known. That
//! distinction matters: `"% *s %s"` has a space flag, which scanf has no
//! syntax for, so the scanf reading is not a reading of that string at all
//! and the printf reading stands alone. Collapsing the two cases silently
//! suppressed every printf format carrying a flag or a precision.

use tree_sitter::Node;

/// What a conversion specification does with the one argument it consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotUse {
    /// The conversion dereferences the pointer it receives: printf `%s` reads
    /// the string it points at, printf `%n` and every assigning scanf
    /// conversion write through it.
    DereferencesPointer,
    /// The conversion consumes the argument without ever dereferencing it --
    /// printf `%p`, which prints the pointer value itself.
    PointerValueOnly,
    /// The conversion consumes an argument that is not a pointer at all: a
    /// printf `%d`, or a `*` standing in for a width or precision. Handing
    /// one a pointer is a type mismatch (FIO47-C's subject), not a
    /// dereference.
    NotAPointer,
    /// Nothing is claimed about this slot -- the conversion character is not
    /// one this model knows, or an earlier unrecognized conversion made every
    /// later slot index unreliable.
    Unknown,
}

/// One family's reading of a format string.
pub enum Reading {
    /// The string parses as this family: one entry per vararg slot, in order,
    /// each carrying the directive text that consumes it.
    Parsed(Vec<(SlotUse, String)>),
    /// The string uses syntax this family does not have -- a printf flag or
    /// precision, for scanf; a `%[` scanset, for printf -- so it is not a
    /// format string of this family, and this reading abstains rather than
    /// reporting that nothing is known.
    OtherFamily,
}

impl Reading {
    /// The use of vararg slot `slot` (0 is the first `...` argument).
    /// `Unknown` past the last conversion -- the call passes more arguments
    /// than the format consumes -- and `Unknown` for an abstaining reading,
    /// whose caller should consult the other family instead.
    pub fn slot_use(&self, slot: usize) -> SlotUse {
        match self {
            Reading::Parsed(slots) => slots
                .get(slot)
                .map(|(use_, _)| *use_)
                .unwrap_or(SlotUse::Unknown),
            Reading::OtherFamily => SlotUse::Unknown,
        }
    }

    /// The directive that consumes `slot`, exactly as written -- `"%s"`,
    /// `"%-20.*ls"`. A `*` width or precision shares its directive with the
    /// conversion that follows it, so two adjacent slots can report the same
    /// text.
    pub fn spec(&self, slot: usize) -> Option<&str> {
        match self {
            Reading::Parsed(slots) => slots.get(slot).map(|(_, spec)| spec.as_str()),
            Reading::OtherFamily => None,
        }
    }

    /// How many vararg slots this reading accounts for.
    pub fn slot_count(&self) -> usize {
        match self {
            Reading::Parsed(slots) => slots.len(),
            Reading::OtherFamily => 0,
        }
    }

    /// True when this family's syntax rules out the string.
    pub fn abstains(&self) -> bool {
        matches!(self, Reading::OtherFamily)
    }
}

/// True when vararg slot `slot` of `format` is dereferenced under every
/// reading of the string that its own syntax permits.
///
/// Requiring that is what lets a caller use this without first establishing
/// which family the callee belongs to, which for an in-tree variadic wrapper
/// is often not resolvable at all: `sqlite3ErrorMsg` reaches sqlite's own
/// formatter and never calls a libc `v*printf`, so there is no libc anchor to
/// follow. Where both readings stand, they agree on `%s`/`%ls` and `%n` --
/// printf reads the string, scanf writes into it -- and disagree everywhere
/// else, since a scanf `%d` writes through an `int *` that printf would read
/// as a value. Where one family's syntax rules the string out, the other
/// reading stands alone.
///
/// The cost is a slot in a format both families could read, whose conversion
/// is not `%s`/`%n`: `sscanf(s, "%d", ip)` with a null `ip` is a real
/// dereference this returns `false` for, because nothing in `"%d"` says the
/// callee reads rather than writes. That is the deliberate trade -- a false
/// *claim* about a dereference is a misfire and always a bug
/// (`docs/adr/0005`), while the missed scanf slot is a bounded recall gap a
/// callee-direction test could close later.
pub fn slot_dereferences_either_direction(format: &str, slot: usize) -> bool {
    let printf = printf_reading(format);
    let scanf = scanf_reading(format);
    let deref = |r: &Reading| r.slot_use(slot) == SlotUse::DereferencesPointer;
    match (printf.abstains(), scanf.abstains()) {
        (false, false) => deref(&printf) && deref(&scanf),
        (false, true) => deref(&printf),
        (true, false) => deref(&scanf),
        (true, true) => false,
    }
}

/// The directive that consumes `slot`, from whichever reading the string's
/// own syntax permits, for a diagnostic that needs to name what it read
/// rather than assert something about the callee.
pub fn slot_spec(format: &str, slot: usize) -> Option<String> {
    let printf = printf_reading(format);
    if !printf.abstains() {
        if let Some(spec) = printf.spec(slot) {
            return Some(spec.to_string());
        }
    }
    scanf_reading(format).spec(slot).map(str::to_string)
}

/// True when `format` contains at least one conversion that consumes an
/// argument, under either reading.
///
/// A variadic callee whose last fixed argument is a string literal is not
/// necessarily a format function -- `execl("/bin/sh", "sh", "-c", cmd, 0)`
/// has that exact shape. A literal with no argument-consuming conversion is
/// evidence that the literal is not a format string, so a caller should fall
/// back to whatever it did before rather than read an empty slot map as
/// "nothing is dereferenced".
pub fn format_consumes_arguments(format: &str) -> bool {
    printf_reading(format).slot_count() > 0 || scanf_reading(format).slot_count() > 0
}

/// Read `format` as a printf-family format string.
pub fn printf_reading(format: &str) -> Reading {
    let f: Vec<char> = format.chars().collect();
    let mut slots: Vec<(SlotUse, String)> = Vec::new();
    // Slots this directive claims before its conversion character is known:
    // a `*` width and a `*` precision each consume an argument of their own.
    let mut pending: Vec<SlotUse> = Vec::new();
    let mut i = 0usize;
    while i < f.len() {
        if f[i] != '%' {
            i += 1;
            continue;
        }
        let directive_start = i;
        i += 1;
        pending.clear();
        macro_rules! flush {
            ($($use_:expr),*) => {{
                $( pending.push($use_); )*
                let spec: String = f[directive_start..i.min(f.len())].iter().collect();
                for use_ in pending.drain(..) {
                    slots.push((use_, spec.clone()));
                }
            }};
        }
        if i >= f.len() {
            flush!(SlotUse::Unknown);
            return Reading::Parsed(slots);
        }
        // `%%` is a literal percent and consumes nothing.
        if f[i] == '%' {
            i += 1;
            continue;
        }
        if is_positional(&f, i) {
            flush!(SlotUse::Unknown);
            return Reading::Parsed(slots);
        }
        while i < f.len() && matches!(f[i], '-' | '+' | ' ' | '#' | '0' | '\'') {
            i += 1;
        }
        // A `*` width or precision consumes its own `int` argument ahead of
        // the conversion's, so it occupies a slot of its own.
        if i < f.len() && f[i] == '*' {
            pending.push(SlotUse::NotAPointer);
            i += 1;
        } else {
            while i < f.len() && f[i].is_ascii_digit() {
                i += 1;
            }
        }
        if i < f.len() && f[i] == '.' {
            i += 1;
            if i < f.len() && f[i] == '*' {
                pending.push(SlotUse::NotAPointer);
                i += 1;
            } else {
                while i < f.len() && f[i].is_ascii_digit() {
                    i += 1;
                }
            }
        }
        i = skip_length_modifier(&f, i);
        if i >= f.len() {
            flush!(SlotUse::Unknown);
            return Reading::Parsed(slots);
        }
        // A `%` where a conversion character belongs is not this directive's
        // conversion -- it opens the next one. sqlite's `%z` is the reason
        // this matters: `z` is a real C length modifier (`%zu`), so reading
        // the `%` of a following `%s` as `%z`'s conversion swallowed that
        // `%s` and lost a slot. Leave `i` on the `%`; the loop re-reads it,
        // and `directive_start` has advanced, so the walk still terminates.
        if f[i] == '%' {
            flush!(SlotUse::Unknown);
            continue;
        }
        let conv = f[i];
        i += 1;
        match conv {
            'd' | 'i' | 'u' | 'o' | 'x' | 'X' | 'f' | 'F' | 'e' | 'E' | 'g' | 'G' | 'a' | 'A'
            | 'c' | 'C' => flush!(SlotUse::NotAPointer),
            's' | 'S' | 'n' => flush!(SlotUse::DereferencesPointer),
            'p' => flush!(SlotUse::PointerValueOnly),
            // glibc's and syslog's `%m` print `strerror(errno)` and consume
            // no argument of their own -- but a `*` width still would.
            'm' => flush!(),
            // A scanset is scanf's alone; printf has no syntax for it.
            '[' => return Reading::OtherFamily,
            // An implementation's own conversion: unknown what it does with
            // its argument, but it takes one, so later slots still line up.
            _ => flush!(SlotUse::Unknown),
        }
    }
    Reading::Parsed(slots)
}

/// Read `format` as a scanf-family format string.
pub fn scanf_reading(format: &str) -> Reading {
    let f: Vec<char> = format.chars().collect();
    let mut slots: Vec<(SlotUse, String)> = Vec::new();
    let mut i = 0usize;
    while i < f.len() {
        if f[i] != '%' {
            i += 1;
            continue;
        }
        let directive_start = i;
        i += 1;
        macro_rules! push {
            ($use_:expr) => {{
                let spec: String = f[directive_start..i.min(f.len())].iter().collect();
                slots.push(($use_, spec));
            }};
        }
        if i >= f.len() {
            push!(SlotUse::Unknown);
            return Reading::Parsed(slots);
        }
        if f[i] == '%' {
            i += 1;
            continue;
        }
        if is_positional(&f, i) {
            push!(SlotUse::Unknown);
            return Reading::Parsed(slots);
        }
        // A printf flag or a precision is syntax scanf does not have, so the
        // string is not a scanf format string and this whole reading
        // abstains. `0` is left out: in scanf position it is the start of a
        // field width, indistinguishable from printf's zero-pad flag.
        if is_printf_only(f[i]) {
            return Reading::OtherFamily;
        }
        // `*` suppresses the assignment: the conversion still happens but
        // consumes no argument, so it takes no slot.
        let suppressed = f[i] == '*';
        if suppressed {
            i += 1;
        }
        if i < f.len() && is_printf_only(f[i]) {
            return Reading::OtherFamily;
        }
        while i < f.len() && f[i].is_ascii_digit() {
            i += 1;
        }
        if i < f.len() && f[i] == '.' {
            return Reading::OtherFamily;
        }
        // `m` here is glibc's allocating modifier (`%ms`), not printf's
        // errno conversion.
        while i < f.len() && matches!(f[i], 'h' | 'l' | 'L' | 'j' | 'z' | 't' | 'q' | 'm') {
            i += 1;
        }
        if i >= f.len() {
            push!(SlotUse::Unknown);
            return Reading::Parsed(slots);
        }
        // As in the printf reading: a `%` here opens the next directive
        // rather than terminating this one.
        if f[i] == '%' {
            push!(SlotUse::Unknown);
            continue;
        }
        let conv = f[i];
        i += 1;
        if conv == '[' {
            // A scanset ends at the first `]` that is not the first
            // character of the set (`%[]abc]` and `%[^]abc]` both put a
            // literal `]` there).
            if i < f.len() && f[i] == '^' {
                i += 1;
            }
            if i < f.len() && f[i] == ']' {
                i += 1;
            }
            while i < f.len() && f[i] != ']' {
                i += 1;
            }
            if i >= f.len() {
                push!(SlotUse::Unknown);
                return Reading::Parsed(slots);
            }
            i += 1;
            if !suppressed {
                push!(SlotUse::DereferencesPointer);
            }
            continue;
        }
        match conv {
            // Every assigning scanf conversion writes through the pointer it
            // is handed, `%p` (a `void **`) and `%n` (an `int *`) included.
            'd' | 'i' | 'u' | 'o' | 'x' | 'X' | 'f' | 'F' | 'e' | 'E' | 'g' | 'G' | 'a' | 'A'
            | 'c' | 'C' | 's' | 'S' | 'p' | 'n' => {
                if !suppressed {
                    push!(SlotUse::DereferencesPointer);
                }
            }
            _ => push!(SlotUse::Unknown),
        }
    }
    Reading::Parsed(slots)
}

/// A character that can appear in a printf directive's prefix and never in a
/// scanf one: the flags and the precision dot.
fn is_printf_only(c: char) -> bool {
    matches!(c, '-' | '+' | ' ' | '#' | '\'' | '.')
}

/// A `%n$` positional reference reorders which argument a conversion
/// consumes, so an in-order slot count stops describing the call. Detected
/// rather than parsed: the callers give up on the whole format string.
fn is_positional(f: &[char], i: usize) -> bool {
    let mut j = i;
    while j < f.len() && f[j].is_ascii_digit() {
        j += 1;
    }
    j > i && j < f.len() && f[j] == '$'
}

/// Skip a printf length modifier: the C ones (`hh`/`h`/`ll`/`l`/`L`/`j`/`z`/
/// `t`, plus the widely-implemented `q`), C23's bit-precise `w`/`wf` forms
/// with their width digits, and MSVC's `I`/`I32`/`I64`.
fn skip_length_modifier(f: &[char], mut i: usize) -> usize {
    if i < f.len() && f[i] == 'I' {
        i += 1;
        while i < f.len() && f[i].is_ascii_digit() {
            i += 1;
        }
        return i;
    }
    while i < f.len() {
        match f[i] {
            'h' | 'l' | 'L' | 'j' | 'z' | 't' | 'q' => i += 1,
            'w' => {
                i += 1;
                if i < f.len() && f[i] == 'f' {
                    i += 1;
                }
                while i < f.len() && f[i].is_ascii_digit() {
                    i += 1;
                }
            }
            _ => break,
        }
    }
    i
}

/// The text between the quotes of a string-literal expression, or `None` when
/// the expression is not a resolvable literal.
///
/// `None` is the answer for a `concatenated_string` that contains anything
/// other than string literals -- `"got %" PRIu64 " bytes"` splices a macro
/// whose expansion carries its own conversion, so the slot map built from the
/// visible halves would be wrong rather than incomplete. Escape sequences are
/// left exactly as written: nothing a `\n` or `\"` expands to changes where a
/// `%` falls.
pub fn string_literal_text(node: &Node, source: &str) -> Option<String> {
    match node.kind() {
        "string_literal" => literal_inner_text(node, source).map(str::to_string),
        "concatenated_string" => {
            let mut joined = String::new();
            for i in 0..node.named_child_count() {
                let child = node.named_child(i)?;
                match child.kind() {
                    "string_literal" => joined.push_str(literal_inner_text(&child, source)?),
                    "string_content" => joined.push_str(child.utf8_text(source.as_bytes()).ok()?),
                    _ => return None,
                }
            }
            Some(joined)
        }
        _ => None,
    }
}

/// The span of a `string_literal` between its opening and closing `"`,
/// dropping any `L`/`u`/`U`/`u8` encoding prefix with it.
fn literal_inner_text<'a>(node: &Node, source: &'a str) -> Option<&'a str> {
    let text = node.utf8_text(source.as_bytes()).ok()?;
    let open = text.find('"')?;
    let close = text.rfind('"')?;
    if close <= open {
        return None;
    }
    Some(&text[open + 1..close])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uses(r: &Reading) -> Vec<SlotUse> {
        (0..r.slot_count()).map(|i| r.slot_use(i)).collect()
    }

    #[test]
    fn a_pointer_value_conversion_is_not_a_dereference() {
        // hostap's `wpa_printf(MSG_ERROR, "wpabuf %p (size=%lu ...)", buf, ...)`
        // shape: slot 0 is the `%p`, and the `%lu`s that follow are not
        // pointers either.
        assert_eq!(
            uses(&printf_reading(
                "wpabuf %p (size=%lu used=%lu) overflow len=%lu"
            )),
            vec![
                SlotUse::PointerValueOnly,
                SlotUse::NotAPointer,
                SlotUse::NotAPointer,
                SlotUse::NotAPointer
            ]
        );
        assert!(!slot_dereferences_either_direction(
            "wpabuf %p (size=%lu)",
            0
        ));
    }

    #[test]
    fn a_string_conversion_dereferences_in_both_directions() {
        assert!(slot_dereferences_either_direction("unknown database %s", 0));
        assert!(slot_dereferences_either_direction("%d %s", 1));
        // Only the scanf reading dereferences a `%d`, and `"%d %s"` is a
        // string both families can read, so the direction-free question
        // answers no.
        assert!(!slot_dereferences_either_direction("%d %s", 0));
        assert_eq!(
            uses(&scanf_reading("%d %s")),
            vec![SlotUse::DereferencesPointer, SlotUse::DereferencesPointer]
        );
    }

    #[test]
    fn a_printf_flag_or_precision_rules_out_the_scanf_reading() {
        // `"% *s %s"` (sqlite ext/qrf): the space is a printf flag, which
        // scanf has no syntax for, so the scanf reading abstains and the
        // printf one stands alone. Collapsing abstention into "nothing is
        // known" suppressed every flagged or precision-bearing format.
        assert!(scanf_reading("% *s %s").abstains());
        assert_eq!(
            uses(&printf_reading("% *s %s")),
            vec![
                SlotUse::NotAPointer,
                SlotUse::DereferencesPointer,
                SlotUse::DereferencesPointer
            ]
        );
        assert!(slot_dereferences_either_direction("% *s %s", 1));
        assert!(slot_dereferences_either_direction("%-20s", 0));
        assert!(slot_dereferences_either_direction("%.8s", 0));
        assert!(slot_dereferences_either_direction("%#x is %s", 1));
        // A scanset is scanf's alone, and the printf reading abstains on it.
        assert!(printf_reading("%[^,]").abstains());
        assert!(slot_dereferences_either_direction("%[^,]", 0));
    }

    #[test]
    fn an_unrecognized_conversion_makes_its_own_slot_unknown_and_no_more() {
        // sqlite's own `%T`/`%#T` conversions: `"oversized integer: %s%#T"`
        // puts the `Expr *` at slot 1.
        let printf = printf_reading("oversized integer: %s%#T");
        assert_eq!(
            uses(&printf),
            vec![SlotUse::DereferencesPointer, SlotUse::Unknown]
        );
        assert!(slot_dereferences_either_direction(
            "oversized integer: %s%#T",
            0
        ));
        assert!(!slot_dereferences_either_direction(
            "oversized integer: %s%#T",
            1
        ));
        assert_eq!(
            printf_reading("unsafe use of %#T()").slot_use(0),
            SlotUse::Unknown
        );
        // The parse continues past it counting one consumed argument, so a
        // later `%s` keeps its slot. sqlite's `"%z%s%s"` and
        // `"unknown join type: %T%s%T%s%T"` are the recurring real cases;
        // stopping instead silenced their genuine `%s` slots.
        assert_eq!(
            uses(&printf_reading("%z%s%s")),
            vec![
                SlotUse::Unknown,
                SlotUse::DereferencesPointer,
                SlotUse::DereferencesPointer
            ]
        );
        assert!(slot_dereferences_either_direction("%z%s%s", 2));
        assert!(slot_dereferences_either_direction(
            "DELETE FROM %Q.%s WHERE %s=%Q",
            1
        ));
        assert!(slot_dereferences_either_direction(
            "unknown join type: %T%s%T%s%T",
            3
        ));
        // Past the last conversion is still unknown: the call passes more
        // arguments than the format consumes.
        assert_eq!(printf_reading("%z%s%s").slot_use(3), SlotUse::Unknown);
    }

    #[test]
    fn a_literal_percent_and_a_star_width_shift_the_slots_differently() {
        assert_eq!(printf_reading("100%% done").slot_count(), 0);
        assert_eq!(
            uses(&printf_reading("%*s")),
            vec![SlotUse::NotAPointer, SlotUse::DereferencesPointer]
        );
        assert_eq!(
            uses(&printf_reading("%.*s")),
            vec![SlotUse::NotAPointer, SlotUse::DereferencesPointer]
        );
        // `%m` prints strerror(errno) and consumes nothing, so the `%s`
        // stays at slot 0.
        assert_eq!(
            uses(&printf_reading("%m: %s")),
            vec![SlotUse::DereferencesPointer]
        );
    }

    #[test]
    fn suppressed_and_scanset_scanf_conversions_count_correctly() {
        assert_eq!(
            uses(&scanf_reading("%*d %[^,] %ms")),
            vec![SlotUse::DereferencesPointer, SlotUse::DereferencesPointer]
        );
        assert_eq!(
            uses(&scanf_reading("%[]ab] %d")),
            vec![SlotUse::DereferencesPointer, SlotUse::DereferencesPointer]
        );
    }

    #[test]
    fn the_conversion_that_consumes_a_slot_can_be_named() {
        assert_eq!(slot_spec("code %d for %s", 1).as_deref(), Some("%s"));
        assert_eq!(slot_spec("%-20.10s", 0).as_deref(), Some("%-20.10s"));
        // A `*` width shares its directive with the conversion after it, so
        // both slots name the same text.
        assert_eq!(slot_spec("%*s", 0).as_deref(), Some("%*s"));
        assert_eq!(slot_spec("%*s", 1).as_deref(), Some("%*s"));
        assert_eq!(slot_spec("%s", 1), None);
        // The printf reading abstains here, so the name comes from the other.
        assert_eq!(slot_spec("%[^,]", 0).as_deref(), Some("%[^,]"));
    }

    #[test]
    fn a_positional_format_is_refused_whole() {
        assert_eq!(uses(&printf_reading("%2$s %1$d")), vec![SlotUse::Unknown]);
        assert!(!slot_dereferences_either_direction("%2$s %1$d", 0));
    }

    #[test]
    fn a_literal_with_no_conversions_is_not_a_format_string() {
        assert!(!format_consumes_arguments("sh"));
        assert!(!format_consumes_arguments("100%%"));
        assert!(format_consumes_arguments("%s"));
        assert!(format_consumes_arguments("%-20s"));
    }

    #[test]
    fn length_modifiers_do_not_hide_the_conversion() {
        assert_eq!(uses(&printf_reading("%llu")), vec![SlotUse::NotAPointer]);
        assert_eq!(uses(&printf_reading("%I64d")), vec![SlotUse::NotAPointer]);
        assert_eq!(uses(&printf_reading("%w32d")), vec![SlotUse::NotAPointer]);
        assert_eq!(
            uses(&printf_reading("%ls")),
            vec![SlotUse::DereferencesPointer]
        );
        assert_eq!(uses(&printf_reading("%lc")), vec![SlotUse::NotAPointer]);
    }
}
