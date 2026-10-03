// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! The integer facts a scan credits: how wide each integer type is, what the
//! `<limits.h>` macros are, and how many bytes `sizeof` gives.
//!
//! Integer widths are implementation-defined (ADR-0011), so the scan credits
//! only what it is told. The facts are plain keys (`int_bits`, `long_bits`,
//! `pointer_bits`, `wchar_t_bits`, `char_signed`, ...). A data model is a
//! named **preset**: a bundle of those keys ([`DataModel::bundle`]), loaded as
//! if its lines were in the project's configuration. Precedence, highest
//! first: the command line, the project's own `[environment]` keys, the
//! selected preset's bundle, and the floor, which is what ISO C guarantees
//! (C11 5.2.4.2.1: `CHAR_BIT` at least 8, `short` and `int` at least 16 bits,
//! `long` at least 32, `long long` at least 64; the conversion-rank order of
//! 6.3.1.1p1; the exact width of an exact-width type such as `int32_t`,
//! 7.20.1.1). `iso`, the default preset, loads nothing. Anything neither the
//! preset nor the project sets is **unknown**.
//!
//! So each question has two answers, queried on the resolved [`IntFacts`]. A
//! guaranteed one (`min_width`, `guaranteed_range`) is what a proof that a
//! value FITS may use: it holds on every conforming implementation. An exact
//! one (`exact_width`, `range`, `limit_macro`, `sizeof_bytes`) is `None`
//! unless a fact fixes it, and a caller must then treat the quantity as
//! unknown in both directions. Nothing outside settings resolution branches
//! on which preset was named.

use serde::{Deserialize, Serialize};

/// Integer conversion rank (C11 6.3.1.1), `Bool` lowest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rank {
    /// `_Bool`.
    Bool,
    /// The three `char` types.
    Char,
    /// `short`.
    Short,
    /// `int`.
    Int,
    /// `long`.
    Long,
    /// `long long`.
    LongLong,
}

/// What a data model knows about one integer type's width: its rank when
/// the model fixes it, the fewest bits it can have, and its exact width when
/// that is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntWidth {
    /// Its conversion rank, when the model fixes it.
    pub rank: Option<Rank>,
    /// The width every implementation gives it at least.
    pub min: u32,
    /// Its exact width, when the model fixes it.
    pub max: Option<u32>,
}

/// Whether the top of a value range is the open end of an integer type
/// rather than a value the code established.
///
/// Under ISO C's widths a side of a type's range that no guard bounds runs to
/// the end of `i64`, and arithmetic on it moves it by the constant involved:
/// `len -= 4` leaves `i64::MAX - 4`. Testing for `i64::MAX` exactly missed
/// every such range, so a guard written after any arithmetic on the variable
/// stopped counting. No value a program establishes sits in the top half of
/// `i64`, so that half is the open end.
pub fn is_open_top(max: i64) -> bool {
    max >= i64::MAX / 2
}

/// [`is_open_top`] for the bottom of a range.
pub fn is_open_bottom(min: i64) -> bool {
    min <= i64::MIN / 2
}

impl IntWidth {
    /// Whether this type may be narrower than `other` on some target the
    /// model allows. Never when it has the same or a higher rank (a higher
    /// rank never has a smaller range, C11 6.3.1.1p1) or is at least as wide
    /// as `other` can be; otherwise when its widths leave room.
    ///
    /// Two types the model describes identically (`size_t` and `size_t`)
    /// count as the same width.
    pub fn may_be_narrower_than(self, other: IntWidth) -> bool {
        if self == other {
            return false;
        }
        if let (Some(a), Some(b)) = (self.rank, other.rank) {
            if a >= b {
                return false;
            }
        }
        other.max.is_none_or(|o| self.min < o)
    }
}

/// A named bundle of the integer facts a project can also write one by one
/// (`[environment]` keys). Selecting a preset loads its bundle as if its lines
/// were in the configuration, under whatever the project declares itself; the
/// scan never branches on which preset was named, only on the resolved
/// [`IntFacts`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataModel {
    /// Loads nothing: only what ISO C guarantees; see the module documentation.
    #[default]
    Iso,
    /// `int`, `long` and pointers 32 bits (32-bit Linux and Windows).
    Ilp32,
    /// `int` 32 bits, `long` and pointers 64 (64-bit Linux, the BSDs, macOS).
    Lp64,
    /// `int` and `long` 32 bits, `long long` and pointers 64 (64-bit Windows).
    Llp64,
}

impl DataModel {
    /// Every preset, in the order `--list-options` shows them.
    pub const ALL: [DataModel; 4] = [
        DataModel::Iso,
        DataModel::Ilp32,
        DataModel::Lp64,
        DataModel::Llp64,
    ];

    /// The preset's name, as `data_model` spells it.
    pub const fn name(self) -> &'static str {
        match self {
            DataModel::Iso => "iso",
            DataModel::Ilp32 => "ilp32",
            DataModel::Lp64 => "lp64",
            DataModel::Llp64 => "llp64",
        }
    }

    /// The facts this preset loads: plain `fact = value` lines. This table is
    /// the only place a preset's widths are written down.
    pub const fn bundle(self) -> &'static [(Fact, u32)] {
        use Fact::*;
        match self {
            DataModel::Iso => &[],
            DataModel::Ilp32 => &[
                (CharBits, 8),
                (ShortBits, 16),
                (IntBits, 32),
                (LongBits, 32),
                (LongLongBits, 64),
                (PointerBits, 32),
                (FloatBytes, 4),
                (DoubleBytes, 8),
                (LongDoubleBytes, 12),
            ],
            DataModel::Lp64 => &[
                (CharBits, 8),
                (ShortBits, 16),
                (IntBits, 32),
                (LongBits, 64),
                (LongLongBits, 64),
                (PointerBits, 64),
                (FloatBytes, 4),
                (DoubleBytes, 8),
                (LongDoubleBytes, 16),
                (TimeTBytes, 8),
                (OffTBytes, 8),
            ],
            // Windows only: its wchar_t is 16 bits.
            DataModel::Llp64 => &[
                (CharBits, 8),
                (ShortBits, 16),
                (IntBits, 32),
                (LongBits, 32),
                (LongLongBits, 64),
                (PointerBits, 64),
                (WcharBits, 16),
                (FloatBytes, 4),
                (DoubleBytes, 8),
                (LongDoubleBytes, 8),
            ],
        }
    }
}

/// One integer fact of the target. [`Fact::overridable`] ones are the
/// `[environment]` keys a project writes; the others are loaded by a preset
/// alone (what the preset's platform fixes besides the widths).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Fact {
    /// `CHAR_BIT`.
    CharBits,
    /// Bits in a `short`.
    ShortBits,
    /// Bits in an `int`.
    IntBits,
    /// Bits in a `long`.
    LongBits,
    /// Bits in a `long long`.
    LongLongBits,
    /// Bits in a pointer, `size_t`, `ptrdiff_t`, `intptr_t` and `uintptr_t`.
    PointerBits,
    /// Bits in a `wchar_t`.
    WcharBits,
    /// Whether plain `char` is signed (1) or unsigned (0).
    CharSigned,
    /// `sizeof(float)`.
    FloatBytes,
    /// `sizeof(double)`.
    DoubleBytes,
    /// `sizeof(long double)`.
    LongDoubleBytes,
    /// `sizeof(time_t)`.
    TimeTBytes,
    /// `sizeof(off_t)`.
    OffTBytes,
}

impl Fact {
    /// Every fact, in `--list-options` order.
    pub const ALL: [Fact; 13] = [
        Fact::CharBits,
        Fact::ShortBits,
        Fact::IntBits,
        Fact::LongBits,
        Fact::LongLongBits,
        Fact::PointerBits,
        Fact::WcharBits,
        Fact::CharSigned,
        Fact::FloatBytes,
        Fact::DoubleBytes,
        Fact::LongDoubleBytes,
        Fact::TimeTBytes,
        Fact::OffTBytes,
    ];

    /// The `[environment]` key (and `--set` name) of this fact.
    pub const fn key(self) -> &'static str {
        match self {
            Fact::CharBits => "char_bits",
            Fact::ShortBits => "short_bits",
            Fact::IntBits => "int_bits",
            Fact::LongBits => "long_bits",
            Fact::LongLongBits => "long_long_bits",
            Fact::PointerBits => "pointer_bits",
            Fact::WcharBits => "wchar_t_bits",
            Fact::CharSigned => "char_signed",
            Fact::FloatBytes => "float_bytes",
            Fact::DoubleBytes => "double_bytes",
            Fact::LongDoubleBytes => "long_double_bytes",
            Fact::TimeTBytes => "time_t_bytes",
            Fact::OffTBytes => "off_t_bytes",
        }
    }

    /// The fact a key names, if it is one.
    pub fn from_key(key: &str) -> Option<Fact> {
        Fact::ALL.into_iter().find(|f| f.key() == key)
    }

    /// Whether a project may write this fact. The rest are loaded by a preset
    /// alone.
    pub const fn overridable(self) -> bool {
        matches!(
            self,
            Fact::ShortBits
                | Fact::IntBits
                | Fact::LongBits
                | Fact::LongLongBits
                | Fact::PointerBits
                | Fact::WcharBits
                | Fact::CharSigned
        )
    }

    /// Whether the fact is a yes/no answer rather than a size.
    pub const fn is_flag(self) -> bool {
        matches!(self, Fact::CharSigned)
    }

    /// The fewest bits ISO C guarantees (C11 5.2.4.2.1), where it guarantees
    /// any: a declared width below it is not a conforming implementation.
    pub const fn minimum_bits(self) -> Option<u32> {
        match self {
            Fact::CharBits => Some(8),
            Fact::ShortBits | Fact::IntBits | Fact::PointerBits => Some(16),
            Fact::LongBits => Some(32),
            Fact::LongLongBits => Some(64),
            // wchar_t holds at least the range of a char (7.20.3).
            Fact::WcharBits => Some(8),
            _ => None,
        }
    }

    /// Whether ISO C guarantees a floor for this fact, so that an unset value
    /// is "at least N bits" rather than unknown.
    pub const fn has_floor(self) -> bool {
        matches!(
            self,
            Fact::CharBits
                | Fact::ShortBits
                | Fact::IntBits
                | Fact::LongBits
                | Fact::LongLongBits
                | Fact::PointerBits
        )
    }

    /// One line saying what the fact is.
    pub const fn description(self) -> &'static str {
        match self {
            Fact::CharBits => "bits in a char (CHAR_BIT)",
            Fact::ShortBits => "bits in a short",
            Fact::IntBits => "bits in an int",
            Fact::LongBits => "bits in a long",
            Fact::LongLongBits => "bits in a long long",
            Fact::PointerBits => "bits in a pointer, size_t, ptrdiff_t and intptr_t",
            Fact::WcharBits => "bits in a wchar_t",
            Fact::CharSigned => "whether plain char is signed",
            Fact::FloatBytes => "sizeof(float)",
            Fact::DoubleBytes => "sizeof(double)",
            Fact::LongDoubleBytes => "sizeof(long double)",
            Fact::TimeTBytes => "sizeof(time_t)",
            Fact::OffTBytes => "sizeof(off_t)",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Where one resolved fact came from, highest precedence first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FactSource {
    /// `--set key=value` or a dedicated flag.
    Cli,
    /// The project's `[environment]`.
    Config,
    /// The selected preset's bundle.
    Preset(DataModel),
    /// Not set anywhere: only the ISO guarantee is known.
    Unknown,
}

impl FactSource {
    /// The word `--list-options` shows.
    pub fn label(self) -> String {
        match self {
            FactSource::Cli => "cli".to_string(),
            FactSource::Config => "config".to_string(),
            FactSource::Preset(model) => format!("preset:{}", model.name()),
            FactSource::Unknown => "unknown".to_string(),
        }
    }
}

/// The resolved integer facts a scan credits: the selected preset's bundle,
/// then the project's own keys, then the command line. Rules and analyses
/// query this one table; a fact nothing sets is unknown, and a proof that
/// needs it may use only the ISO guarantee (`min_width`, `guaranteed_range`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IntFacts {
    values: [Option<u32>; 13],
    sources: [FactSource; 13],
}

impl Default for IntFacts {
    fn default() -> Self {
        IntFacts::ISO
    }
}

impl From<DataModel> for IntFacts {
    fn from(model: DataModel) -> Self {
        IntFacts::preset(model)
    }
}

impl IntFacts {
    /// Nothing declared: the ISO guarantees alone.
    pub const ISO: IntFacts = IntFacts::preset(DataModel::Iso);
    /// The `ilp32` bundle alone.
    pub const ILP32: IntFacts = IntFacts::preset(DataModel::Ilp32);
    /// The `lp64` bundle alone.
    pub const LP64: IntFacts = IntFacts::preset(DataModel::Lp64);
    /// The `llp64` bundle alone.
    pub const LLP64: IntFacts = IntFacts::preset(DataModel::Llp64);

    /// The facts `model`'s bundle loads, and nothing else.
    pub const fn preset(model: DataModel) -> IntFacts {
        let mut facts = IntFacts {
            values: [None; 13],
            sources: [FactSource::Unknown; 13],
        };
        let bundle = model.bundle();
        let mut i = 0;
        while i < bundle.len() {
            let (fact, value) = bundle[i];
            facts.values[fact.index()] = Some(value);
            facts.sources[fact.index()] = FactSource::Preset(model);
            i += 1;
        }
        facts
    }

    /// Record `value` for `fact`, from `source`: a higher-precedence layer
    /// replaces what a lower one set.
    pub fn set(&mut self, fact: Fact, value: u32, source: FactSource) {
        self.values[fact.index()] = Some(value);
        self.sources[fact.index()] = source;
    }

    /// The value of `fact`, when something set it.
    pub fn get(&self, fact: Fact) -> Option<u32> {
        self.values[fact.index()]
    }

    /// Every fact's value, in [`Fact::ALL`] order: a key for a table built
    /// from the facts.
    pub fn values(&self) -> [Option<u32>; 13] {
        self.values
    }

    /// Where `fact` came from.
    pub fn source(&self, fact: Fact) -> FactSource {
        self.sources[fact.index()]
    }

    /// The facts a project or the command line declared (not a preset's),
    /// for the settings hash and the resolved-settings JSON.
    pub fn declared(&self) -> impl Iterator<Item = (Fact, u32)> + '_ {
        Fact::ALL.into_iter().filter_map(|f| {
            matches!(self.source(f), FactSource::Cli | FactSource::Config)
                .then(|| self.get(f).map(|v| (f, v)))
                .flatten()
        })
    }

    /// Every fact and its value (`unknown` where nothing sets it), in one
    /// string: what a prescan cache records so that facts collected under
    /// one set of widths are never reused under another.
    pub fn fingerprint(&self) -> String {
        Fact::ALL
            .iter()
            .map(|f| match self.get(*f) {
                Some(v) => format!("{}={v}", f.key()),
                None => format!("{}=unknown", f.key()),
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Whether plain `char` is signed, when declared. No preset says.
    pub fn char_signed(&self) -> Option<bool> {
        self.get(Fact::CharSigned).map(|v| v != 0)
    }

    /// Bits in a `wchar_t`, when declared or loaded by the preset.
    pub fn wchar_bits(&self) -> Option<u32> {
        self.get(Fact::WcharBits)
    }

    /// Whether the widths of `short`, `int` and `long` are all fixed: a
    /// target the scan can answer "does this fit" about without guessing.
    pub fn int_width_is_fixed(&self) -> bool {
        self.get(Fact::IntBits).is_some()
    }

    /// The problems a set of facts has, one per line: a width below the ISO
    /// minimum, a width that is no whole number of bytes or exceeds 64 bits,
    /// and a rank order (`short <= int <= long <= long long`) broken among the
    /// widths that are known.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        for fact in Fact::ALL {
            let Some(value) = self.get(fact) else {
                continue;
            };
            if fact.is_flag() {
                if value > 1 {
                    out.push(format!("{}: expected true or false", fact.key()));
                }
                continue;
            }
            // A preset's bundle is valid by construction; check what a project
            // or the command line wrote.
            if !matches!(self.source(fact), FactSource::Cli | FactSource::Config) {
                continue;
            }
            if let Some(min) = fact.minimum_bits() {
                if value < min {
                    out.push(format!(
                        "{} = {value} is below the {min} bits ISO C guarantees (C11 5.2.4.2.1)",
                        fact.key()
                    ));
                }
            }
            if fact.minimum_bits().is_some() && (value % 8 != 0 || value > 64) {
                out.push(format!(
                    "{} = {value}: a width is a whole number of 8-bit bytes, up to 64 bits",
                    fact.key()
                ));
            }
        }
        let ranked = [
            Fact::ShortBits,
            Fact::IntBits,
            Fact::LongBits,
            Fact::LongLongBits,
        ];
        let known: Vec<(Fact, u32)> = ranked
            .into_iter()
            .filter_map(|f| self.get(f).map(|v| (f, v)))
            .collect();
        for pair in known.windows(2) {
            if pair[0].1 > pair[1].1 {
                out.push(format!(
                    "{} = {} is wider than {} = {}: ranks must not shrink (short <= int <= long <= long long, C11 6.3.1.1)",
                    pair[0].0.key(),
                    pair[0].1,
                    pair[1].0.key(),
                    pair[1].1
                ));
            }
        }
        out
    }
}

impl IntFacts {
    /// The width in bits of an integer of `rank` when the facts fix it.
    /// `_Bool` holds exactly 0 and 1 everywhere.
    pub fn exact_width(&self, rank: Rank) -> Option<u32> {
        match rank {
            Rank::Bool => Some(1),
            Rank::Char => self.get(Fact::CharBits),
            Rank::Short => self.get(Fact::ShortBits),
            Rank::Int => self.get(Fact::IntBits),
            Rank::Long => self.get(Fact::LongBits),
            Rank::LongLong => self.get(Fact::LongLongBits),
        }
    }

    /// The width in bits every implementation gives an integer of `rank` at
    /// least (C11 5.2.4.2.1), or the exact width when the facts fix it.
    pub fn min_width(&self, rank: Rank) -> u32 {
        self.exact_width(rank).unwrap_or(match rank {
            Rank::Bool => 1,
            Rank::Char => 8,
            Rank::Short | Rank::Int => 16,
            Rank::Long => 32,
            Rank::LongLong => 64,
        })
    }

    /// The exact range of an integer of `rank`, when the facts fix it.
    /// Signed types are two's complement.
    pub fn range(&self, signed: bool, rank: Rank) -> Option<(i128, i128)> {
        let width = self.exact_width(rank)?;
        Some(if rank == Rank::Bool {
            (0, 1)
        } else if signed {
            (-(1i128 << (width - 1)), (1i128 << (width - 1)) - 1)
        } else {
            (0, (1i128 << width) - 1)
        })
    }

    /// The range every implementation's integer of `rank` holds at least:
    /// every value in it is representable wherever the code is built (the
    /// C11 5.2.4.2.1 magnitudes, whose signed minimum is `-(2^(N-1) - 1)`),
    /// or the exact range when the facts fix it.
    pub fn guaranteed_range(&self, signed: bool, rank: Rank) -> (i128, i128) {
        if let Some(range) = self.range(signed, rank) {
            return range;
        }
        let width = self.min_width(rank);
        if signed {
            (-((1i128 << (width - 1)) - 1), (1i128 << (width - 1)) - 1)
        } else {
            (0, (1i128 << width) - 1)
        }
    }

    /// What the facts know about the width of an integer of `rank`.
    pub fn width_of(&self, rank: Rank) -> IntWidth {
        IntWidth {
            rank: Some(rank),
            min: self.min_width(rank),
            max: self.exact_width(rank),
        }
    }

    /// The signedness (`true` for unsigned) and width of the integer type a
    /// spelling names: a standard integer type in its usual spellings, an
    /// exact-width `<stdint.h>` type, or `size_t`, `ssize_t`, `ptrdiff_t`,
    /// `intptr_t` and `uintptr_t`. `None` for anything else: a typedef not
    /// yet followed, a struct, a pointer. Plain `char` answers "not
    /// unsigned" only in the sense that it is not declared so; whether it is
    /// signed is implementation-defined.
    pub fn spelled_width(&self, spelling: &str) -> Option<(bool, IntWidth)> {
        let exact = |unsigned, bits: u32| {
            let rank = [
                Rank::Char,
                Rank::Short,
                Rank::Int,
                Rank::Long,
                Rank::LongLong,
            ]
            .into_iter()
            .find(|r| self.exact_width(*r) == Some(bits));
            Some((
                unsigned,
                IntWidth {
                    rank,
                    min: bits,
                    max: Some(bits),
                },
            ))
        };
        let word = |unsigned| {
            // The lowest rank as wide as a pointer: `int` on ilp32, `long` on
            // lp64, `long long` on llp64.
            let rank = self.pointer_width().and_then(|bits| {
                [Rank::Int, Rank::Long, Rank::LongLong]
                    .into_iter()
                    .find(|r| self.exact_width(*r) == Some(bits))
            });
            Some((
                unsigned,
                IntWidth {
                    rank,
                    min: self.pointer_width().unwrap_or(16),
                    max: self.pointer_width(),
                },
            ))
        };
        let t = spelling.trim();
        let rank = match t {
            "char" | "signed char" | "unsigned char" => Rank::Char,
            "short" | "signed short" | "unsigned short" | "short int" | "signed short int"
            | "unsigned short int" => Rank::Short,
            "int" | "signed" | "unsigned" | "signed int" | "unsigned int" => Rank::Int,
            "long" | "signed long" | "unsigned long" | "long int" | "signed long int"
            | "unsigned long int" => Rank::Long,
            "long long"
            | "signed long long"
            | "unsigned long long"
            | "long long int"
            | "signed long long int"
            | "unsigned long long int" => Rank::LongLong,
            "int8_t" => return exact(false, 8),
            "uint8_t" => return exact(true, 8),
            "int16_t" => return exact(false, 16),
            "uint16_t" => return exact(true, 16),
            "int32_t" => return exact(false, 32),
            "uint32_t" => return exact(true, 32),
            "int64_t" => return exact(false, 64),
            "uint64_t" => return exact(true, 64),
            "ssize_t" | "ptrdiff_t" | "intptr_t" => return word(false),
            "size_t" | "uintptr_t" => return word(true),
            _ => return None,
        };
        Some((t.starts_with("unsigned"), self.width_of(rank)))
    }

    /// The width in bits of a pointer, or of `size_t`, `ptrdiff_t`,
    /// `intptr_t` and `uintptr_t`, when the facts fix it.
    pub fn pointer_width(&self) -> Option<u32> {
        self.get(Fact::PointerBits)
    }

    /// `sizeof` an integer of `rank`, in bytes, when the facts fix it: its
    /// width over `CHAR_BIT`, so unknown until `CHAR_BIT` is. The `char`
    /// types are 1 by definition (C11 6.5.3.4p4).
    pub fn sizeof_bytes(&self, rank: Rank) -> Option<u32> {
        match rank {
            Rank::Char => Some(1),
            Rank::Bool => self.get(Fact::CharBits).map(|_| 1),
            _ => Some(self.exact_width(rank)? / self.get(Fact::CharBits)?),
        }
    }

    /// `sizeof(wchar_t)`, when `wchar_t_bits` and `CHAR_BIT` are known.
    pub fn wchar_bytes(&self) -> Option<u32> {
        Some(self.wchar_bits()? / self.get(Fact::CharBits)?)
    }

    /// The value of a `<limits.h>` or `<stdint.h>` limit macro when it is
    /// fixed. The exact-width macros (`INT32_MAX`, `UINT8_MAX`, ...) are
    /// fixed always (C11 7.20.2.1); the others when the facts fix the width.
    /// `CHAR_MIN` and `CHAR_MAX` need `char_signed` as well: no preset says
    /// whether plain `char` is signed. A value outside `i64` is `None`.
    pub fn limit_macro(&self, name: &str) -> Option<i64> {
        let exact = |bits: u32, signed: bool, max: bool| -> Option<i64> {
            let v: i128 = match (signed, max) {
                (true, true) => (1i128 << (bits - 1)) - 1,
                (true, false) => -(1i128 << (bits - 1)),
                (false, _) => (1i128 << bits) - 1,
            };
            i64::try_from(v).ok()
        };
        let exact_width = match name {
            "INT8_MAX" => Some((8, true, true)),
            "INT8_MIN" => Some((8, true, false)),
            "UINT8_MAX" => Some((8, false, true)),
            "INT16_MAX" => Some((16, true, true)),
            "INT16_MIN" => Some((16, true, false)),
            "UINT16_MAX" => Some((16, false, true)),
            "INT32_MAX" => Some((32, true, true)),
            "INT32_MIN" => Some((32, true, false)),
            "UINT32_MAX" => Some((32, false, true)),
            "INT64_MAX" => Some((64, true, true)),
            "INT64_MIN" => Some((64, true, false)),
            _ => None,
        };
        if let Some((bits, signed, max)) = exact_width {
            return exact(bits, signed, max);
        }
        if matches!(name, "CHAR_MIN" | "CHAR_MAX") {
            let signed = self.char_signed()?;
            let (lo, hi) = self.range(signed, Rank::Char)?;
            return i64::try_from(if name == "CHAR_MAX" { hi } else { lo }).ok();
        }
        let (signed, rank, max) = match name {
            "CHAR_BIT" => return self.exact_width(Rank::Char).map(i64::from),
            "SCHAR_MAX" => (true, Rank::Char, true),
            "SCHAR_MIN" => (true, Rank::Char, false),
            "UCHAR_MAX" => (false, Rank::Char, true),
            "SHRT_MAX" => (true, Rank::Short, true),
            "SHRT_MIN" => (true, Rank::Short, false),
            "USHRT_MAX" => (false, Rank::Short, true),
            "INT_MAX" => (true, Rank::Int, true),
            "INT_MIN" => (true, Rank::Int, false),
            "UINT_MAX" => (false, Rank::Int, true),
            "LONG_MAX" => (true, Rank::Long, true),
            "LONG_MIN" => (true, Rank::Long, false),
            "ULONG_MAX" => (false, Rank::Long, true),
            "LLONG_MAX" => (true, Rank::LongLong, true),
            "LLONG_MIN" => (true, Rank::LongLong, false),
            _ => return None,
        };
        let (lo, hi) = self.range(signed, rank)?;
        i64::try_from(if max { hi } else { lo }).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_knows_only_the_minimums_and_the_exact_width_types() {
        let iso = IntFacts::ISO;
        assert_eq!(iso.exact_width(Rank::Int), None);
        assert_eq!(iso.min_width(Rank::Int), 16);
        assert_eq!(iso.min_width(Rank::Long), 32);
        assert_eq!(iso.guaranteed_range(true, Rank::Int), (-32767, 32767));
        assert_eq!(iso.guaranteed_range(false, Rank::Char), (0, 255));
        assert_eq!(iso.range(true, Rank::Int), None);
        assert_eq!(iso.limit_macro("INT_MAX"), None);
        assert_eq!(iso.limit_macro("CHAR_BIT"), None);
        assert_eq!(iso.limit_macro("INT32_MAX"), Some(2147483647));
        assert_eq!(iso.limit_macro("INT8_MIN"), Some(-128));
        assert_eq!(iso.sizeof_bytes(Rank::Char), Some(1));
        assert_eq!(iso.sizeof_bytes(Rank::Int), None);
        assert_eq!(iso.pointer_width(), None);
    }

    #[test]
    fn a_preset_loads_a_bundle_and_no_preset_names_wchar_or_char_signedness() {
        assert_eq!(IntFacts::LP64.exact_width(Rank::Long), Some(64));
        assert_eq!(IntFacts::LLP64.exact_width(Rank::Long), Some(32));
        assert_eq!(IntFacts::ILP32.pointer_width(), Some(32));
        // Only the Windows-only model loads wchar_t, and no preset loads
        // whether plain char is signed.
        assert_eq!(IntFacts::LP64.wchar_bits(), None);
        assert_eq!(IntFacts::ILP32.wchar_bits(), None);
        assert_eq!(IntFacts::LLP64.wchar_bits(), Some(16));
        for model in DataModel::ALL {
            assert_eq!(IntFacts::preset(model).char_signed(), None, "{model:?}");
        }
        assert_eq!(IntFacts::LP64.limit_macro("INT_MAX"), Some(2147483647));
        assert_eq!(IntFacts::LP64.limit_macro("LONG_MAX"), Some(i64::MAX));
        assert_eq!(IntFacts::LLP64.limit_macro("LONG_MAX"), Some(2147483647));
        assert_eq!(IntFacts::LP64.limit_macro("ULONG_MAX"), None);
        assert_eq!(IntFacts::LP64.sizeof_bytes(Rank::Long), Some(8));
        assert_eq!(
            IntFacts::LP64.guaranteed_range(true, Rank::Int).0,
            -2147483648
        );
    }

    #[test]
    fn char_signedness_makes_char_max_and_char_min_numbers() {
        let mut facts = IntFacts::LP64;
        assert_eq!(facts.limit_macro("CHAR_MAX"), None);
        assert_eq!(facts.limit_macro("CHAR_MIN"), None);
        facts.set(Fact::CharSigned, 1, FactSource::Config);
        assert_eq!(facts.limit_macro("CHAR_MAX"), Some(127));
        assert_eq!(facts.limit_macro("CHAR_MIN"), Some(-128));
        facts.set(Fact::CharSigned, 0, FactSource::Config);
        assert_eq!(facts.limit_macro("CHAR_MAX"), Some(255));
        assert_eq!(facts.limit_macro("CHAR_MIN"), Some(0));
        // Without CHAR_BIT there is no number even when the sign is declared.
        let mut iso = IntFacts::ISO;
        iso.set(Fact::CharSigned, 1, FactSource::Config);
        assert_eq!(iso.limit_macro("CHAR_MAX"), None);
    }

    #[test]
    fn an_override_beats_the_preset_and_the_command_line_beats_both() {
        let mut facts = IntFacts::LP64;
        assert_eq!(
            facts.source(Fact::IntBits),
            FactSource::Preset(DataModel::Lp64)
        );
        facts.set(Fact::IntBits, 16, FactSource::Config);
        assert_eq!(facts.exact_width(Rank::Int), Some(16));
        assert_eq!(facts.source(Fact::IntBits), FactSource::Config);
        facts.set(Fact::IntBits, 32, FactSource::Cli);
        assert_eq!(facts.source(Fact::IntBits), FactSource::Cli);
        assert_eq!(
            facts.source(Fact::LongBits),
            FactSource::Preset(DataModel::Lp64)
        );
        assert_eq!(facts.source(Fact::WcharBits), FactSource::Unknown);
        assert_eq!(
            facts.declared().collect::<Vec<_>>(),
            vec![(Fact::IntBits, 32)]
        );
    }

    #[test]
    fn a_width_below_the_iso_minimum_or_out_of_rank_order_is_a_problem() {
        let with = |fact, value| {
            let mut facts = IntFacts::ISO;
            facts.set(fact, value, FactSource::Config);
            facts.problems()
        };
        assert!(with(Fact::IntBits, 32).is_empty());
        assert!(with(Fact::IntBits, 8)[0].contains("below the 16 bits"));
        assert!(with(Fact::LongBits, 16)[0].contains("below the 32 bits"));
        assert!(with(Fact::LongLongBits, 32)[0].contains("below the 64 bits"));
        assert!(with(Fact::IntBits, 20)[0].contains("whole number of 8-bit bytes"));
        assert!(with(Fact::PointerBits, 128)[0].contains("up to 64 bits"));
        // Rank order among the widths that are known: int 64 over a declared
        // long of 32.
        let mut facts = IntFacts::ISO;
        facts.set(Fact::IntBits, 64, FactSource::Config);
        facts.set(Fact::LongBits, 32, FactSource::Config);
        let problems = facts.problems();
        assert!(
            problems.iter().any(|p| p.contains("ranks must not shrink")),
            "{problems:?}"
        );
        // An unknown width breaks no order: int 64 over an unset long is fine.
        assert!(with(Fact::IntBits, 64).is_empty());
    }
}
