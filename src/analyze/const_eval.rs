//! Lightweight constant evaluation and value-range analysis for macro constants.
//!
//! Resolves `#define` macro constants and propagates value ranges through
//! arithmetic expressions. Used by INT32-C and INT30-C to suppress false
//! positives when expressions provably fit within type limits.
//!
//! This is NOT a full CFG-based dataflow — it's syntactic constant folding
//! plus loop-bound ancestor walks.

use crate::analyze::dead_regions::DeadRegions;
use crate::analyze::macro_expand::{self, FunctionMacro};
use crate::utility::cert_c::ast_utils;
use crate::utility::cert_c::data_model::{DataModel, Rank};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use tree_sitter::Node;

/// Map of macro name → constant integer value.
pub type MacroConstantMap = HashMap<String, i64>;

/// Map of variable name → value range.
pub type VarRangeMap = HashMap<String, ValueRange>;

/// An integer value range [min, max].
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ValueRange {
    /// Lower bound, inclusive.
    pub min: i64,
    /// Upper bound, inclusive.
    pub max: i64,
}

impl ValueRange {
    /// A range containing exactly one value.
    pub fn exact(val: i64) -> Self {
        Self { min: val, max: val }
    }

    /// A range from `min` to `max`, inclusive.
    pub fn new(min: i64, max: i64) -> Self {
        Self { min, max }
    }

    /// The empty set, spelled as the inverted range `[MAX, MIN]`.
    ///
    /// This is the lattice bottom: intersecting anything with it stays
    /// empty, and joining anything with it gives the other operand back
    /// unchanged -- both fall out of the plain min/max arithmetic, so no
    /// caller needs a special case. It exists so a condition that no value
    /// can satisfy (`x > 5 && x < 3`) keeps a range of its own instead of
    /// collapsing to "no constraint", which is the opposite claim.
    pub fn empty() -> Self {
        Self {
            min: i64::MAX,
            max: i64::MIN,
        }
    }

    /// The range of `self + other`, or `None` on overflow.
    pub fn add(&self, other: &ValueRange) -> Option<Self> {
        let min = self.min.checked_add(other.min)?;
        let max = self.max.checked_add(other.max)?;
        Some(Self { min, max })
    }

    /// The range of `self - other`, or `None` on overflow.
    pub fn sub(&self, other: &ValueRange) -> Option<Self> {
        let min = self.min.checked_sub(other.max)?;
        let max = self.max.checked_sub(other.min)?;
        Some(Self { min, max })
    }

    /// The range of `self * other`, or `None` on overflow.
    pub fn mul(&self, other: &ValueRange) -> Option<Self> {
        // For multiplication, all four corners must be checked
        let corners = [
            self.min.checked_mul(other.min)?,
            self.min.checked_mul(other.max)?,
            self.max.checked_mul(other.min)?,
            self.max.checked_mul(other.max)?,
        ];
        Some(Self {
            min: *corners.iter().min().unwrap(),
            max: *corners.iter().max().unwrap(),
        })
    }

    /// The range of `self << other`, or `None` if the shift amount is out of
    /// range or the result would overflow. Negative shift amounts are
    /// clamped to 0 (a negative shift is UB in C, so unreachable in
    /// correct code).
    pub fn shl(&self, other: &ValueRange) -> Option<Self> {
        if other.max > 63 || other.max < 0 {
            return None;
        }
        // Clamp negative lower bound to 0: negative shifts are UB in C,
        // so in correct code only the non-negative range is reachable.
        let shift_min = other.min.max(0);
        let other = ValueRange::new(shift_min, other.max);
        let corners = [
            self.min.checked_shl(other.min as u32)?,
            self.min.checked_shl(other.max as u32)?,
            self.max.checked_shl(other.min as u32)?,
            self.max.checked_shl(other.max as u32)?,
        ];
        Some(Self {
            min: *corners.iter().min().unwrap(),
            max: *corners.iter().max().unwrap(),
        })
    }

    /// The range of `self >> other`, or `None` when the bound would not be
    /// sound: either operand possibly negative, or a shift amount that can
    /// reach the width of the value being shifted.
    ///
    /// C leaves `>>` of a negative left operand implementation-defined and a
    /// shift at or past the operand's width undefined, so a range straddling
    /// either boundary carries no usable bound. Over non-negative operands
    /// the result is monotone — rising with the value, falling with the
    /// amount — so the two extremes are the only corners worth taking.
    pub fn shr(&self, other: &ValueRange) -> Option<Self> {
        if self.min < 0 || other.min < 0 || other.max > 63 {
            return None;
        }
        Some(Self {
            min: self.min >> other.max,
            max: self.max >> other.min,
        })
    }

    /// Bitwise AND range: `self & other`.
    ///
    /// For non-negative operands the result is bounded by `min(self.max, other.max)` —
    /// the classical mask-upper-bound approximation.  Returns `None` when either
    /// operand may be negative (signed bitwise AND is implementation-defined in C).
    pub fn bitand(&self, other: &ValueRange) -> Option<Self> {
        if self.min < 0 || other.min < 0 {
            return None;
        }
        Some(Self {
            min: 0,
            max: self.max.min(other.max),
        })
    }

    /// The range of `self / other`, or `None` when the divisor range spans
    /// zero (a possible division by zero bounds nothing) or a corner overflows
    /// `i64`.
    ///
    /// `a / b` is monotone in each argument once `b` keeps a fixed sign, so —
    /// as with multiplication — the extremes sit at the four corners. Those
    /// corners are what carry `INT_MIN / -1` upward: the quotient 2147483648
    /// leaves the 32-bit signed band, and it is `expression_overflows_signed_vra`,
    /// not this method, that calls that an overflow.
    pub fn div(&self, other: &ValueRange) -> Option<Self> {
        if other.min <= 0 && other.max >= 0 {
            return None;
        }
        let corners = [
            self.min.checked_div(other.min)?,
            self.min.checked_div(other.max)?,
            self.max.checked_div(other.min)?,
            self.max.checked_div(other.max)?,
        ];
        Some(Self {
            min: *corners.iter().min().unwrap(),
            max: *corners.iter().max().unwrap(),
        })
    }

    /// The range of `self % other`, or `None` when the divisor range spans
    /// zero. C truncates toward zero, so the remainder takes the dividend's
    /// sign and its magnitude stays strictly below the largest magnitude the
    /// divisor can take.
    ///
    /// This bounds a `%` result; it cannot itself signal the one case where
    /// `%` is undefined (`INT_MIN % -1`, undefined because the corresponding
    /// division overflows). That signal comes from `div` on the same operands.
    pub fn rem(&self, other: &ValueRange) -> Option<Self> {
        if other.min <= 0 && other.max >= 0 {
            return None;
        }
        let magnitude = other.min.checked_abs()?.max(other.max.checked_abs()?);
        let bound = magnitude.checked_sub(1)?;
        Some(Self {
            min: if self.min < 0 { -bound } else { 0 },
            max: if self.max > 0 { bound } else { 0 },
        })
    }

    /// Returns true if every value in this range fits in a signed integer of the given bit width.
    pub fn fits_in_signed(&self, bits: u32) -> bool {
        if bits == 0 || bits > 64 {
            return false;
        }
        if bits == 64 {
            return true; // i64 always fits in 64-bit signed
        }
        let type_min = -(1i64 << (bits - 1));
        let type_max = (1i64 << (bits - 1)) - 1;
        self.min >= type_min && self.max <= type_max
    }

    /// Returns true if every value in this range fits in an unsigned integer of the given bit width.
    pub fn fits_in_unsigned(&self, bits: u32) -> bool {
        if bits == 0 || bits > 64 {
            return false;
        }
        if self.min < 0 {
            return false;
        }
        if bits >= 64 {
            return true;
        }
        let type_max = (1i64 << bits) - 1;
        self.max <= type_max
    }
}

/// The value range a narrow integer type takes on after C's usual arithmetic
/// conversions promote it to `int` — i.e. its own full representable range,
/// since integer promotion is value-preserving — when `model` fixes it. `None`
/// for anything already `int`-wide or wider, which promotion leaves alone, and
/// for a type whose width `model` leaves open: under ISO C's widths a `short`
/// is at least 16 bits and possibly more, so its range is not known, while an
/// `int16_t` is exactly 16 everywhere.
///
/// Plain `char`'s signedness is implementation-defined, so it is given the
/// union of both interpretations.
///
/// Seeding a [`VarRangeMap`] with these before calling
/// [`try_evaluate_range`] is what lets a rule prove the thing promotion
/// guarantees on a declared model: no `+`, `-` or `*` over two promoted narrow
/// operands can leave a 32-bit `int` (the widest such product, `-32768 *
/// -32768`, is under `INT_MAX`). The range is exact, so it bounds every value
/// the type holds: what a proof that something cannot overflow needs. A rule
/// that wants a witness instead wants [`guaranteed_range_for_type`].
pub fn promoted_range_for_type(type_name: &str, model: DataModel) -> Option<ValueRange> {
    narrow_range(type_name, model, false)
}

/// The range a narrow integer type holds on every implementation `model`
/// allows: its exact range on a declared model, and under ISO C's widths the
/// C11 5.2.4.2.1 minimum magnitudes (`short` at least `[-32767, 32767]`, plain
/// `char` at least the `[0, 127]` both signednesses share). Every value in it
/// is one the type can hold wherever the code is built, so arithmetic over
/// these ranges that leaves `int` is a witness of overflow on some target.
pub fn guaranteed_range_for_type(type_name: &str, model: DataModel) -> Option<ValueRange> {
    narrow_range(type_name, model, true)
}

fn narrow_range(type_name: &str, model: DataModel, guaranteed: bool) -> Option<ValueRange> {
    let t = type_name.trim();
    let range = |r: (i128, i128)| Some(ValueRange::new(r.0 as i64, r.1 as i64));
    let exact_width = |signed: bool, bits: u32| {
        range(if signed {
            (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1)
        } else {
            (0, (1i128 << bits) - 1)
        })
    };
    let ranked = |signed: bool, rank: Rank| match model.range(signed, rank) {
        Some(r) => range(r),
        None if guaranteed => range(model.guaranteed_range(signed, rank)),
        None => None,
    };
    match t {
        "char" => {
            let (s, u) = (ranked(true, Rank::Char)?, ranked(false, Rank::Char)?);
            Some(if guaranteed {
                ValueRange::new(s.min.max(u.min), s.max.min(u.max))
            } else {
                ValueRange::new(s.min.min(u.min), s.max.max(u.max))
            })
        }
        "signed char" => ranked(true, Rank::Char),
        "unsigned char" => ranked(false, Rank::Char),
        "int8_t" => exact_width(true, 8),
        "uint8_t" => exact_width(false, 8),
        "short" | "signed short" | "short int" | "signed short int" => ranked(true, Rank::Short),
        "unsigned short" | "unsigned short int" => ranked(false, Rank::Short),
        "int16_t" => exact_width(true, 16),
        "uint16_t" => exact_width(false, 16),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Built-in constants: limit macros (<limits.h>, <stdint.h>) and sizeof
// ---------------------------------------------------------------------------

/// The builtin type spellings whose `sizeof` a data model may fix, with what
/// decides each.
const SIZEOF_SPELLINGS: &[(&str, SizeOf)] = &[
    ("char", SizeOf::Char),
    ("signed char", SizeOf::Char),
    ("unsigned char", SizeOf::Char),
    ("int8_t", SizeOf::Char),
    ("uint8_t", SizeOf::Char),
    ("bool", SizeOf::Rank(Rank::Bool)),
    ("_Bool", SizeOf::Rank(Rank::Bool)),
    ("short", SizeOf::Rank(Rank::Short)),
    ("short int", SizeOf::Rank(Rank::Short)),
    ("signed short", SizeOf::Rank(Rank::Short)),
    ("unsigned short", SizeOf::Rank(Rank::Short)),
    ("int16_t", SizeOf::Exact(16)),
    ("uint16_t", SizeOf::Exact(16)),
    ("int", SizeOf::Rank(Rank::Int)),
    ("signed int", SizeOf::Rank(Rank::Int)),
    ("unsigned int", SizeOf::Rank(Rank::Int)),
    ("signed", SizeOf::Rank(Rank::Int)),
    ("unsigned", SizeOf::Rank(Rank::Int)),
    ("int32_t", SizeOf::Exact(32)),
    ("uint32_t", SizeOf::Exact(32)),
    ("long", SizeOf::Rank(Rank::Long)),
    ("signed long", SizeOf::Rank(Rank::Long)),
    ("unsigned long", SizeOf::Rank(Rank::Long)),
    ("long int", SizeOf::Rank(Rank::Long)),
    ("signed long int", SizeOf::Rank(Rank::Long)),
    ("unsigned long int", SizeOf::Rank(Rank::Long)),
    ("long long", SizeOf::Rank(Rank::LongLong)),
    ("signed long long", SizeOf::Rank(Rank::LongLong)),
    ("unsigned long long", SizeOf::Rank(Rank::LongLong)),
    ("long long int", SizeOf::Rank(Rank::LongLong)),
    ("signed long long int", SizeOf::Rank(Rank::LongLong)),
    ("unsigned long long int", SizeOf::Rank(Rank::LongLong)),
    ("int64_t", SizeOf::Exact(64)),
    ("uint64_t", SizeOf::Exact(64)),
    ("size_t", SizeOf::Pointer),
    ("ssize_t", SizeOf::Pointer),
    ("ptrdiff_t", SizeOf::Pointer),
    ("void *", SizeOf::Pointer),
    ("wchar_t", SizeOf::WideChar),
    ("float", SizeOf::Float),
    ("double", SizeOf::Double),
    ("long double", SizeOf::LongDouble),
    ("time_t", SizeOf::Lp64Only(8)),
    ("off_t", SizeOf::Lp64Only(8)),
];

/// What decides one builtin type's `sizeof`.
#[derive(Clone, Copy)]
enum SizeOf {
    /// 1, by definition (C11 6.5.3.4p4).
    Char,
    /// The data model's size for an integer of this rank.
    Rank(Rank),
    /// An exact-width type: its width over an 8-bit `char`, which only a
    /// declared model states (ISO C guarantees `CHAR_BIT` at least 8).
    Exact(u32),
    /// A pointer's size, which `size_t` and `ptrdiff_t` share on every
    /// declared model.
    Pointer,
    /// `wchar_t`: 4 bytes on the Unix models, 2 on Windows.
    WideChar,
    /// `float`: implementation-defined like the integers, 4 on every
    /// declared model's ABI.
    Float,
    /// `double`: 8 on every declared model's ABI.
    Double,
    /// `long double`: 12 on i386, 16 on x86-64, 8 with MSVC.
    LongDouble,
    /// A POSIX type with this size on LP64 only (`time_t`, `off_t`, whose
    /// 32-bit sizes depend on build flags).
    Lp64Only(i64),
}

/// `size`'s bytes under `model`, or `None` when the model leaves it open.
fn sizeof_under(model: DataModel, size: SizeOf) -> Option<i64> {
    let declared = model != DataModel::Iso;
    let bytes = match size {
        SizeOf::Char => 1,
        SizeOf::Rank(rank) => model.sizeof_bytes(rank)?.into(),
        SizeOf::Exact(bits) if declared => i64::from(bits / 8),
        SizeOf::Pointer => (model.pointer_width()? / 8).into(),
        SizeOf::WideChar => match model {
            DataModel::Iso => return None,
            DataModel::Llp64 => 2,
            DataModel::Ilp32 | DataModel::Lp64 => 4,
        },
        SizeOf::Float if declared => 4,
        SizeOf::Double if declared => 8,
        SizeOf::LongDouble => match model {
            DataModel::Iso => return None,
            DataModel::Ilp32 => 12,
            DataModel::Lp64 => 16,
            DataModel::Llp64 => 8,
        },
        SizeOf::Lp64Only(bytes) if model == DataModel::Lp64 => bytes,
        _ => return None,
    };
    Some(bytes)
}

/// The `<limits.h>` and `<stdint.h>` macros a data model may fix.
const LIMIT_MACROS: &[&str] = &[
    "CHAR_BIT",
    "SCHAR_MAX",
    "SCHAR_MIN",
    "UCHAR_MAX",
    "SHRT_MAX",
    "SHRT_MIN",
    "USHRT_MAX",
    "INT_MAX",
    "INT_MIN",
    "UINT_MAX",
    "LONG_MAX",
    "LONG_MIN",
    "ULONG_MAX",
    "LLONG_MAX",
    "LLONG_MIN",
    "INT8_MAX",
    "INT8_MIN",
    "INT16_MAX",
    "INT16_MIN",
    "INT32_MAX",
    "INT32_MIN",
    "INT64_MAX",
    "INT64_MIN",
    "UINT8_MAX",
    "UINT16_MAX",
    "UINT32_MAX",
];

/// The constants every translation unit has under `model`: the limit macros
/// it fixes ([`DataModel::limit_macro`]) and, under `sizeof(T)` keys no C
/// identifier can collide with, the `sizeof` of each builtin type it fixes.
/// Under [`DataModel::Iso`], the default, that is the exact-width limits
/// (`INT32_MAX`) and `sizeof` the `char` types: `INT_MAX` and `sizeof(long)`
/// are not constants a scan may assume (ADR-0011). Built once per model.
pub fn builtin_constants(model: DataModel) -> &'static MacroConstantMap {
    static TABLES: LazyLock<[MacroConstantMap; 4]> = LazyLock::new(|| {
        [
            DataModel::Iso,
            DataModel::Ilp32,
            DataModel::Lp64,
            DataModel::Llp64,
        ]
        .map(|model| {
            let mut m = MacroConstantMap::new();
            for name in LIMIT_MACROS {
                if let Some(v) = model.limit_macro(name) {
                    m.insert((*name).into(), v);
                }
            }
            for (spelling, size) in SIZEOF_SPELLINGS {
                if let Some(v) = sizeof_under(model, *size) {
                    m.insert(format!("sizeof({spelling})"), v);
                }
            }
            m
        })
    });
    &TABLES[match model {
        DataModel::Iso => 0,
        DataModel::Ilp32 => 1,
        DataModel::Lp64 => 2,
        DataModel::Llp64 => 3,
    }]
}

// ---------------------------------------------------------------------------
// sizeof resolution
// ---------------------------------------------------------------------------

/// Resolve `sizeof(type)` to a constant from `macros`, where
/// [`builtin_constants`] filed the sizes the data model fixes. The `char`
/// types are 1 everywhere; a pointer type has the size of `void *`. `None`
/// for a type whose size is not fixed or not known.
fn resolve_sizeof_type(type_text: &str, macros: &MacroConstantMap) -> Option<i64> {
    let t = type_text.split_whitespace().collect::<Vec<_>>().join(" ");
    if matches!(t.as_str(), "char" | "signed char" | "unsigned char") {
        return Some(1);
    }
    let key = if t.ends_with('*') {
        "sizeof(void *)".to_string()
    } else {
        format!("sizeof({t})")
    };
    macros.get(&key).copied()
}

/// What every conforming implementation guarantees of `sizeof(type)` when
/// [`resolve_sizeof_type`] cannot fix it: an exact-width type has exactly N
/// bits and no padding (C11 7.20.1.1) over a `char` of at least 8 bits
/// (5.2.4.2.1), so its size is between 1 and N/8. `None` for any other type.
fn sizeof_type_bounds(type_text: &str) -> Option<ValueRange> {
    let t = type_text.split_whitespace().collect::<Vec<_>>().join(" ");
    SIZEOF_SPELLINGS.iter().find_map(|(s, size)| match size {
        SizeOf::Exact(bits) if *s == t => Some(ValueRange::new(1, i64::from(bits / 8))),
        _ => None,
    })
}

/// Whether `type_text` names a builtin type whose `sizeof` only the data
/// model can fix, so an unknown answer is not "some object of at least one
/// byte".
fn is_builtin_sized_type(type_text: &str) -> bool {
    let t = type_text.split_whitespace().collect::<Vec<_>>().join(" ");
    SIZEOF_SPELLINGS.iter().any(|(s, _)| *s == t)
}

// ---------------------------------------------------------------------------
// Macro constant collection
// ---------------------------------------------------------------------------

/// Collect `#define NAME "string"` patterns and return a map from name → raw quoted value.
/// Used to check whether a macro expands to an absolute path string.
pub fn collect_string_literal_macros(root: &Node, source: &str) -> HashMap<String, String> {
    let mut raw_defs: Vec<(String, String)> = Vec::new();
    collect_preproc_defs(root, source, &mut raw_defs);

    let mut string_macros = HashMap::new();
    for (name, value) in raw_defs {
        let v = value.trim();
        if v.starts_with('"') && v.ends_with('"') && v.len() >= 2 {
            string_macros.insert(name, v.to_string());
        } else if v.starts_with("L\"") && v.ends_with('"') && v.len() >= 3 {
            // Wide string literal L"..." — strip the L prefix, keep "..."
            string_macros.insert(name, v[1..].to_string());
        }
    }
    string_macros
}

fn is_absolute_path_inner(inner: &str) -> bool {
    inner.starts_with('/')
        || (inner.len() >= 3
            && inner
                .chars()
                .next()
                .map(|c| c.is_ascii_alphabetic())
                .unwrap_or(false)
            && inner.chars().nth(1) == Some(':')
            && (inner.chars().nth(2) == Some('\\') || inner.chars().nth(2) == Some('/')))
        || inner.starts_with("\\\\")
}

/// Return true if `name` is a macro whose value is a relative-path OS command string —
/// non-empty, not starting with a space or dash (argument fragment), and not an absolute path.
/// This distinguishes `BAD_OS_COMMAND = "ls -la"` (relative command) from
/// `SAFE_CMD_ARGS = " -la"` (argument fragment) and `GOOD_OS_COMMAND = "/usr/bin/ls"` (absolute).
pub fn is_relative_command_macro(string_macros: &HashMap<String, String>, name: &str) -> bool {
    let Some(value) = string_macros.get(name) else {
        return false;
    };
    let inner = &value[1..value.len() - 1];
    // Must be non-empty after trimming
    if inner.trim().is_empty() {
        return false;
    }
    // Starts with space or dash → argument fragment, not a standalone command
    if inner.starts_with(' ') || inner.starts_with('-') {
        return false;
    }
    // Absolute path → safe
    !is_absolute_path_inner(inner)
}

/// Return true if `name` is a macro whose string value is safe to use as a
/// `strcpy`/`strcat` source for a command variable. Safe means either an
/// absolute-path macro or an argument-fragment macro (value starts with
/// whitespace or `–` — these are option strings appended to an established path,
/// never standalone relative-command names).
pub fn is_safe_command_macro(string_macros: &HashMap<String, String>, name: &str) -> bool {
    let Some(value) = string_macros.get(name) else {
        return false;
    };
    let inner = &value[1..value.len() - 1];
    // Absolute path → safe
    if is_absolute_path_inner(inner) {
        return true;
    }
    // Empty string → safe (no-op strcat)
    if inner.is_empty() {
        return true;
    }
    // Argument fragment (starts with space or dash) → safe to append
    inner.starts_with(' ') || inner.starts_with('-')
}

/// Collect `#define ALIAS func_name` patterns where the value is a single C identifier.
/// These represent macro aliases for function names (e.g., `#define SYSTEM system`).
/// Returns a map from alias → target identifier.
///
/// Only a SETTLED alias is returned: one every live definition in the file
/// points at the same target. raylib's `CHDIR` is `_chdir` in one arm and
/// `chdir` in the other, and which definition was met last used to decide
/// what every call to it was; such a name is left to resolve to itself, and
/// [`collect_macro_alias_alternatives`] keeps all of its targets.
pub fn collect_macro_aliases(root: &Node, source: &str) -> HashMap<String, String> {
    settled_aliases(&collect_macro_alias_alternatives(root, source))
}

/// Every live target of each `#define ALIAS target` in the file, in file
/// order, each distinct target once. See [`collect_macro_aliases`].
pub fn collect_macro_alias_alternatives(root: &Node, source: &str) -> HashMap<String, Vec<String>> {
    let mut raw_defs: Vec<(String, String)> = Vec::new();
    collect_preproc_defs(root, source, &mut raw_defs);

    let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
    for (name, value) in &raw_defs {
        let v = value.trim();
        // A function alias is a single C identifier (no operators, parens, digits-only, etc.)
        if !v.is_empty()
            && v.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !v.chars().next().unwrap_or('0').is_ascii_digit()
            // Skip pure integer strings (they're constants, not function aliases)
            && v.parse::<i64>().is_err()
        {
            let targets = aliases.entry(name.clone()).or_default();
            if !targets.iter().any(|t| t == v) {
                targets.push(v.to_string());
            }
        }
    }
    aliases
}

/// The aliases among `alternatives` that have exactly one target.
pub fn settled_aliases(alternatives: &HashMap<String, Vec<String>>) -> HashMap<String, String> {
    alternatives
        .iter()
        .filter(|(_, targets)| targets.len() == 1)
        .map(|(name, targets)| (name.clone(), targets[0].clone()))
        .collect()
}

/// Fold one file's alias targets into the project-wide alternatives, each
/// distinct target once.
pub fn merge_macro_alias_alternatives(
    into: &mut HashMap<String, Vec<String>>,
    from: HashMap<String, Vec<String>>,
) {
    for (name, targets) in from {
        let slot = into.entry(name).or_default();
        for target in targets {
            if !slot.contains(&target) {
                slot.push(target);
            }
        }
    }
}

/// [`merged_macro_aliases`] for the alternatives: the project's, with each
/// name the current file defines replaced by the file's own targets.
pub fn merged_macro_alias_alternatives(
    project: &HashMap<String, Vec<String>>,
    root: &Node,
    source: &str,
) -> HashMap<String, Vec<String>> {
    let mut alternatives = project.clone();
    alternatives.extend(collect_macro_alias_alternatives(root, source));
    alternatives
}

/// Add to `aliases` each name that `alternatives` does not settle but that
/// some live definition resolves to an identifier `accept` takes, mapped to
/// that identifier. For a rule an alias accuses through (ADR-0010 D1, per
/// consumer): it keeps resolving names through its one map, and the build in
/// which the alias IS the callee it looks for still reaches it.
pub fn with_accusing_alias_targets(
    aliases: &mut HashMap<String, String>,
    alternatives: &HashMap<String, Vec<String>>,
    accept: impl Fn(&str) -> bool,
) {
    for (name, targets) in alternatives {
        if targets.len() < 2 || aliases.contains_key(name) {
            continue;
        }
        if let Some(target) = resolve_macro_alias_where(alternatives, name, &accept) {
            if target != *name {
                aliases.insert(name.clone(), target);
            }
        }
    }
}

/// Add to `aliases` each name that `alternatives` does not settle but whose
/// every live target (resolved through `aliases`) has the same `role`, mapped
/// to the first such target. For a rule an alias SUPPRESSES through (ADR-0010
/// D1, per consumer): one arm is not enough, but an alias that is `free` in
/// one build and a declared deallocator of the same argument in the other
/// frees that argument in every build. A target with no role, or two targets
/// whose roles differ, leaves the name unsettled.
pub fn with_agreeing_alias_targets<R: PartialEq>(
    aliases: &mut HashMap<String, String>,
    alternatives: &HashMap<String, Vec<String>>,
    role: impl Fn(&str) -> Option<R>,
) {
    let mut agreed = Vec::new();
    for (name, targets) in alternatives {
        if targets.len() < 2 || aliases.contains_key(name) {
            continue;
        }
        let resolved: Vec<&str> = targets
            .iter()
            .map(|t| resolve_macro_alias(aliases, t))
            .collect();
        let Some(first) = resolved.first().and_then(|t| role(t)) else {
            continue;
        };
        if resolved[1..]
            .iter()
            .all(|t| role(t).is_some_and(|r| r == first))
            && resolved[0] != name.as_str()
        {
            agreed.push((name.clone(), resolved[0].to_string()));
        }
    }
    aliases.extend(agreed);
}

/// The first identifier reachable from `name` through any live alias
/// definition (`alternatives`) that `accept` takes, trying `name` itself
/// first; `None` when no chain reaches one. For a consumer an alias ACCUSES
/// through (ADR-0010 D1, per consumer): a build in which `CHDIR` is `chdir`
/// is enough for a finding about `chdir`, whatever the other arms say.
/// Breadth-first in file order, bounded like [`resolve_macro_alias`].
pub fn resolve_macro_alias_where(
    alternatives: &HashMap<String, Vec<String>>,
    name: &str,
    accept: impl Fn(&str) -> bool,
) -> Option<String> {
    let mut frontier = vec![name.to_string()];
    let mut seen: HashSet<String> = HashSet::new();
    for _ in 0..8 {
        let mut next = Vec::new();
        for current in frontier {
            if !seen.insert(current.clone()) {
                continue;
            }
            if accept(&current) {
                return Some(current);
            }
            if let Some(targets) = alternatives.get(&current) {
                next.extend(targets.iter().cloned());
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    None
}

/// Follow `#define ALIAS target` chains from `name` to the identifier they
/// end at: `mbedtls_calloc` -> `calloc`, or `name` itself when it is not an
/// alias. Bounded, so a `#define a b` / `#define b a` pair terminates.
///
/// An object-like alias is the one way a project renames an allocator that
/// no other engine sees: `macro_expand` handles function-like macros only,
/// and a bare-identifier body is not a constant. A rule that dispatches on
/// callee name (`free`, `calloc`, a summary lookup) should resolve through
/// this first, or every `mbedtls_calloc(...)` in mbedtls is invisible to it
/// while `mbedtls_free(...)` is caught only by a `*_free` name guess
/// .
pub fn resolve_macro_alias<'a>(aliases: &'a HashMap<String, String>, name: &'a str) -> &'a str {
    let mut current = name;
    for _ in 0..8 {
        match aliases.get(current) {
            Some(target) if target != current => current = target.as_str(),
            _ => break,
        }
    }
    current
}

/// Merge cross-file macro aliases (`project`, from [`super::context::ProjectContext::macro_aliases`])
/// with aliases collected from the current file, with per-file definitions
/// winning on name collisions. This is the common `set_project_context` +
/// `check` idiom shared by rules that consume [`collect_macro_aliases`]
/// (e.g. STR02-C, ERR33-C, ENV03-C, ENV33-C).
pub fn merged_macro_aliases(
    project: &HashMap<String, String>,
    root: &Node,
    source: &str,
) -> HashMap<String, String> {
    let mut aliases = project.clone();
    for (name, targets) in collect_macro_alias_alternatives(root, source) {
        // The file's own definitions decide, and a name it defines more
        // than one way resolves to itself here even when the project
        // settled it.
        if let [target] = targets.as_slice() {
            aliases.insert(name, target.clone());
        } else {
            aliases.remove(&name);
        }
    }
    aliases
}

/// Walk `preproc_def` nodes in the AST to collect `#define NAME value` constants.
/// Handles decimal, hex, octal literals, expressions, and references to other macros.
/// Recurses into `preproc_ifdef/if/ifndef` blocks.
/// Includes the [`builtin_constants`] `model` fixes (`INT_MAX` on a declared
/// model, `sizeof(T)`); a file's own `#define` of such a name wins over the
/// builtin, since that definition is what its code compiles with (ADR-0006).
pub fn collect_macro_constants(root: &Node, source: &str, model: DataModel) -> MacroConstantMap {
    let mut macros = builtin_constants(model).clone();
    // Two-pass: first collect all raw definitions, then resolve references
    let mut raw_defs: Vec<(String, String)> = Vec::new();
    collect_preproc_defs(root, source, &mut raw_defs);
    // Also collect file-scope `static const int NAME = VALUE;` declarations
    collect_static_const_defs(root, source, &mut raw_defs);
    // Also collect file-scope `static int NAME = VALUE;` (no const) when never reassigned
    collect_non_const_static_defs(root, source, &mut raw_defs);
    // Collect `enum { NAME = VALUE, ... }` enumerators as compile-time constants
    collect_enum_constants(root, source, &mut raw_defs);
    for (name, _) in &raw_defs {
        macros.remove(name);
    }

    // Iteratively resolve — handles forward references and chains
    let mut changed = true;
    let mut iterations = 0;
    while changed && iterations < 5 {
        changed = false;
        iterations += 1;
        for (name, value_text) in &raw_defs {
            if macros.contains_key(name) {
                continue;
            }
            if let Some(val) = try_evaluate_text(value_text.trim(), &macros) {
                macros.insert(name.clone(), val);
                changed = true;
            }
        }
    }
    macros
}

/// Merge cross-file macro constants (`project`, from
/// [`super::context::ProjectContext::macro_constants`]) with constants collected from the
/// current file, with per-file definitions winning on name collisions. This
/// is the common `set_project_context` + `check` idiom shared by rules that
/// consume [`collect_macro_constants`] (e.g. INT30-C, INT32-C, INT34-C,
/// ARR30-C).
pub fn merged_macro_constants(
    project: &MacroConstantMap,
    root: &Node,
    source: &str,
    model: DataModel,
) -> MacroConstantMap {
    let mut macros = project.clone();
    macros.extend(collect_macro_constants(root, source, model));
    macros
}

/// Collect raw `#define NAME value` pairs from the AST, in file order.
///
/// A definition inside a branch the assumed platform never compiles is
/// skipped ([`DeadRegions`]): the callers otherwise take hostap's
/// `#define close closesocket` (`_MSC_VER` arm of `common.h`) as an alias no
/// POSIX build ever has, and whichever of a `#ifdef _WIN32` / `#else` pair
/// their tie-break favours (aliases: last wins; constants: first wins) is
/// the Windows value half the time.
/// [`collect_macro_constants`] less every name whose value is not fixed in
/// every configuration, for a caller that treats a constant condition as
/// PROOF a branch never runs (the CFG's dead-branch pruning). Name
/// resolution may pick among a macro's live definitions (ADR-0010 D3);
/// pruning a branch on that pick removes code another configuration runs
/// (D1, D8). Left out:
/// - a name whose live definitions disagree across `#if` arms
///   (`#ifdef FAST #define MODE 1 #else #define MODE 0 #endif`);
/// - an overridable default, defined only under `#ifndef NAME` /
///   `#if !defined(NAME)`: a build passing `-DNAME=1` gets another value.
pub fn cfg_prunable_constants(root: &Node, source: &str, model: DataModel) -> MacroConstantMap {
    let mut constants = collect_macro_constants(root, source, model);
    for name in config_dependent_constant_names(root, source) {
        constants.remove(&name);
    }
    constants
}

/// The names [`cfg_prunable_constants`] leaves out of this file's constants:
/// defined differently across live arms, or only as an overridable default.
/// The prescan unions them project-wide
/// (`ProjectContext::config_dependent_constants`) so a rule pruning branches
/// with the project's macro constants can leave out a header's defaults too.
pub fn config_dependent_constant_names(root: &Node, source: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut raw: Vec<(String, String)> = Vec::new();
    collect_preproc_defs(root, source, &mut raw);
    collect_static_const_defs(root, source, &mut raw);
    collect_non_const_static_defs(root, source, &mut raw);
    let mut texts: HashMap<&str, HashSet<&str>> = HashMap::new();
    for (name, value) in &raw {
        texts.entry(name.as_str()).or_default().insert(value.trim());
    }
    for (name, values) in texts {
        if values.len() > 1 {
            out.insert(name.to_string());
        }
    }
    for def in lang_parsing_substrate::query::find_descendants_of_kind(*root, "preproc_def") {
        let Some(name) = def
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source.as_bytes()).ok())
        else {
            continue;
        };
        if is_default_for_itself(&def, name, source) {
            out.insert(name.to_string());
        }
    }
    out
}

/// Whether `def` (a `#define name ...`) sits under `#ifndef name` or
/// `#if !defined(name)`: a default a build can override with `-Dname=...`.
/// Asked directly rather than through `dead_regions::arm_assumptions`, which
/// skips include guards, and `#ifndef TRACE` / `#define TRACE 0` / `#endif`
/// at file scope has exactly an include guard's shape. A real guard macro
/// caught here is harmless: no one tests `if (FOO_H)`.
fn is_default_for_itself(def: &Node, name: &str, source: &str) -> bool {
    let text = |n: Node| n.utf8_text(source.as_bytes()).unwrap_or("").to_string();
    let mut child = *def;
    while let Some(parent) = child.parent() {
        let in_then_arm = parent
            .child_by_field_name("alternative")
            .is_none_or(|a| a.id() != child.id());
        match parent.kind() {
            "preproc_ifdef" if in_then_arm => {
                let ifndef = parent.child(0).is_some_and(|d| text(d).ends_with("ndef"));
                if ifndef
                    && parent
                        .child_by_field_name("name")
                        .is_some_and(|n| text(n) == name)
                {
                    return true;
                }
            }
            "preproc_if" if in_then_arm => {
                let cond = parent
                    .child_by_field_name("condition")
                    .map(|c| text(c).split_whitespace().collect::<String>())
                    .unwrap_or_default();
                if cond == format!("!defined({name})") || cond == format!("!defined{name}") {
                    return true;
                }
            }
            _ => {}
        }
        child = parent;
    }
    false
}

fn collect_preproc_defs(node: &Node, source: &str, defs: &mut Vec<(String, String)>) {
    let dead = DeadRegions::of(source);
    collect_preproc_defs_rec(node, source, &dead, defs);
}

fn collect_preproc_defs_rec(
    node: &Node,
    source: &str,
    dead: &DeadRegions,
    defs: &mut Vec<(String, String)>,
) {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "preproc_def" => {
                    if dead.contains_node(&child) {
                        continue;
                    }
                    // preproc_def has children: name (identifier), value (preproc_arg)
                    let name = child
                        .child_by_field_name("name")
                        .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                        .unwrap_or("")
                        .to_string();
                    let value = child
                        .child_by_field_name("value")
                        .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    if !name.is_empty() && !value.is_empty() {
                        // Skip function-like macros (have parenthesized params)
                        if !value.starts_with('(')
                            || value.chars().filter(|&c| c == '(').count()
                                == value.chars().filter(|&c| c == ')').count()
                        {
                            defs.push((name, value));
                        }
                    }
                }
                // Recurse into nested preproc constructs (#if/#ifdef bodies),
                // ERROR nodes, and extern "C" linkage blocks:
                //
                // - ERROR: a single unrelated syntax error elsewhere in a
                //   large #ifndef-guarded block can make tree-sitter-c fall
                //   back to one giant ERROR node wrapping the rest of the
                //   file -- the `preproc_def` children underneath are still
                //   individually well-formed and worth collecting even
                //   though their ancestor is an error-recovery node.
                // - linkage_specification/declaration_list: the standard
                //   `#ifdef __cplusplus extern "C" { #endif ... }` C/C++
                //   interop idiom (virtually every public C header) parses
                //   as a `linkage_specification` whose body is a
                //   `declaration_list` -- without recursing into these, EVERY
                //   #define inside that near-universal wrapper (i.e. most of
                //   the file, in practice) was invisible to macro-constant
                //   collection (found via curl.h's CURLINFO_*
                //   macros all sitting inside its `extern "C" { ... }` block).
                kind if kind.starts_with("preproc_")
                    || kind == "ERROR"
                    || kind == "linkage_specification"
                    || kind == "declaration_list" =>
                {
                    collect_preproc_defs_rec(&child, source, dead, defs);
                }
                _ => {}
            }
        }
    }
}

/// Collect file-scope `static const int NAME = VALUE;` and `const int NAME = VALUE;`
/// declarations. These behave as compile-time constants in C.
fn collect_static_const_defs(root: &Node, source: &str, defs: &mut Vec<(String, String)>) {
    for i in 0..root.child_count() {
        let child = match root.child(i) {
            Some(c) => c,
            None => continue,
        };
        if child.kind() != "declaration" {
            continue;
        }
        let decl_text = child.utf8_text(source.as_bytes()).unwrap_or("").to_string();
        // Must contain "const" and an integer/bool type; a volatile object
        // may change unseen (C11 6.7.3p7) and is never a constant.
        if !decl_text.contains("const") || contains_token(&decl_text, "volatile") {
            continue;
        }
        // Check for integer type keywords
        let has_int_type = decl_text.contains("int")
            || decl_text.contains("long")
            || decl_text.contains("short")
            || decl_text.contains("char")
            || decl_text.contains("_Bool");
        if !has_int_type {
            continue;
        }
        // Extract init_declarator children for `NAME = VALUE`
        for j in 0..child.named_child_count() {
            let gc = match child.named_child(j) {
                Some(c) => c,
                None => continue,
            };
            if gc.kind() != "init_declarator" {
                continue;
            }
            // Look for identifier and value
            let mut name = None;
            let mut value = None;
            for k in 0..gc.named_child_count() {
                if let Some(ggc) = gc.named_child(k) {
                    if ggc.kind() == "identifier" && name.is_none() {
                        name = ggc.utf8_text(source.as_bytes()).ok().map(|s| s.to_string());
                    } else if ggc.kind() == "number_literal" && name.is_some() {
                        value = ggc.utf8_text(source.as_bytes()).ok().map(|s| s.to_string());
                    }
                }
            }
            if let (Some(n), Some(v)) = (name, value) {
                defs.push((n, v));
            }
        }
    }
}

/// Collect file-scope `static int NAME = VALUE;` declarations (no `const`) that
/// are never reassigned in the file. These behave as effective compile-time
/// constants in Juliet and similar controlled test patterns.
fn collect_non_const_static_defs(root: &Node, source: &str, defs: &mut Vec<(String, String)>) {
    let mut candidates: Vec<(String, String, usize)> = Vec::new();

    for i in 0..root.child_count() {
        let child = match root.child(i) {
            Some(c) => c,
            None => continue,
        };
        if child.kind() != "declaration" {
            continue;
        }
        let decl_text = child.utf8_text(source.as_bytes()).unwrap_or("");
        // Must have `static` but NOT `const` (const handled by collect_static_const_defs),
        // and not `volatile`, which may change unseen (C11 6.7.3p7).
        if !decl_text.contains("static")
            || decl_text.contains("const")
            || contains_token(decl_text, "volatile")
        {
            continue;
        }
        let has_int_type = decl_text.contains("int")
            || decl_text.contains("long")
            || decl_text.contains("short")
            || decl_text.contains("_Bool");
        if !has_int_type {
            continue;
        }
        let decl_end = child.end_byte();

        for j in 0..child.named_child_count() {
            let gc = match child.named_child(j) {
                Some(c) => c,
                None => continue,
            };
            if gc.kind() != "init_declarator" {
                continue;
            }
            let mut name = None;
            let mut value = None;
            for k in 0..gc.named_child_count() {
                if let Some(ggc) = gc.named_child(k) {
                    if ggc.kind() == "identifier" && name.is_none() {
                        name = ggc.utf8_text(source.as_bytes()).ok().map(|s| s.to_string());
                    } else if ggc.kind() == "number_literal" && name.is_some() {
                        value = ggc.utf8_text(source.as_bytes()).ok().map(|s| s.to_string());
                    }
                }
            }
            if let (Some(n), Some(v)) = (name, value) {
                candidates.push((n, v, decl_end));
            }
        }
    }

    let function_macros = function_macro_names(source);
    for (name, value, _decl_end) in candidates {
        if file_static_never_written_among(root, source, &name, &function_macros) {
            defs.push((name, value));
        }
    }
}

/// Whether nothing in the translation unit `root` can change the file-scope
/// object `name` after its initializer: no occurrence that binds to it (a
/// local or parameter of the same name is another object, ADR-0006) is an
/// assignment target, a `++`/`--` operand, or has its address taken with
/// `&` (after which any pointer write may reach it). Only then is a
/// `static int staticFalse = 0;` (Juliet's flow variants) an effective
/// constant (ADR-0011 basis 3: proof in the scanned source). The text scan
/// this replaces saw `x = ` and `x++` but not `++x`, `&x` handed out, or a
/// local `x` shadowing the static, so the CFG pruned branches that run.
/// A non-`static` object has external linkage and another file can write it;
/// callers ask this only of `static` ones.
///
/// Conservative where the parse cannot see: the name anywhere in a
/// `#define` body, or inside the arguments of a function-like macro this
/// file defines, counts as a write, and a block-scope `extern` declaration
/// of the name is the file-scope object, not another one.
pub fn file_static_never_written(root: &Node, source: &str, name: &str) -> bool {
    file_static_never_written_among(root, source, name, &function_macro_names(source))
}

/// The names `source` defines as function-like macros, collected once so a
/// per-identifier question does not rescan the file.
pub fn function_macro_names(source: &str) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    crate::analyze::macro_expand::collect_function_macro_names(source, &mut out);
    out
}

/// [`file_static_never_written`] with the file's function-like macro names
/// ([`function_macro_names`]) already collected, for a caller asking about
/// several names.
pub fn file_static_never_written_among(
    root: &Node,
    source: &str,
    name: &str,
    function_macros: &std::collections::HashSet<String>,
) -> bool {
    use crate::utility::cert_c::ast_utils::{
        declaration_has_storage_class, resolve_identifier_binding, IdentifierBinding,
    };
    // A macro body is one token to the parser, so a write in it is
    // invisible to the walk below: any mention of the name in a `#define`
    // body counts as a write.
    if name_in_a_define_body(source, name) {
        return false;
    }
    let ids = lang_parsing_substrate::query::find_descendants_of_kind(*root, "identifier");
    for id in ids {
        if id.utf8_text(source.as_bytes()).unwrap_or("") != name {
            continue;
        }
        match resolve_identifier_binding(&id, name, source) {
            // A block-scope `extern int x;` names the file-scope object.
            Some(IdentifierBinding::Local(decl))
                if !declaration_has_storage_class(&decl, "extern", source) =>
            {
                continue
            }
            Some(IdentifierBinding::Parameter(_)) => continue,
            _ => {}
        }
        if is_write_context(&id) || is_function_macro_argument(&id, source, function_macros) {
            return false;
        }
    }
    true
}

/// Every name this translation unit may write as a FILE-SCOPE object, by
/// the same evidence [`file_static_never_written`] reads for one name: an
/// occurrence that does not bind to a local or parameter (a block-scope
/// `extern` binds to the file-scope object) standing as an assignment
/// target, a `++`/`--` operand, the operand of `&`, or inside the
/// arguments of a function-like macro this file defines; plus every
/// identifier in any `#define` body, which the parse cannot see into.
///
/// For an object with external linkage the union of this over every
/// scanned file is the whole in-tree write set (ADR-0006: `extern int g;`
/// in another file is the same object), so a name in none of them is never
/// written by the scanned source.
pub fn file_scope_written_names(root: &Node, source: &str) -> std::collections::HashSet<String> {
    use crate::utility::cert_c::ast_utils::{
        declaration_has_storage_class, resolve_identifier_binding, IdentifierBinding,
    };
    let mut out = define_body_identifiers(source);
    let function_macros = function_macro_names(source);
    for id in lang_parsing_substrate::query::find_descendants_of_kind(*root, "identifier") {
        let name = id.utf8_text(source.as_bytes()).unwrap_or("");
        if name.is_empty() || out.contains(name) {
            continue;
        }
        if !is_write_context(&id) && !is_function_macro_argument(&id, source, &function_macros) {
            continue;
        }
        match resolve_identifier_binding(&id, name, source) {
            Some(IdentifierBinding::Local(decl))
                if !declaration_has_storage_class(&decl, "extern", source) => {}
            Some(IdentifierBinding::Parameter(_)) => {}
            _ => {
                out.insert(name.to_string());
            }
        }
    }
    out
}

/// Names this translation unit declares `static` at file scope (all
/// preprocessor arms): objects and functions with internal linkage, which
/// no other file's code can name.
pub fn file_scope_static_names(root: &Node, source: &str) -> std::collections::HashSet<String> {
    use crate::utility::cert_c::ast_utils::{
        declaration_has_storage_class, get_identifier_from_declarator,
    };
    fn walk(n: &Node, source: &str, out: &mut std::collections::HashSet<String>) {
        for i in 0..n.child_count() {
            let Some(child) = n.child(i) else { continue };
            match child.kind() {
                "declaration" if declaration_has_storage_class(&child, "static", source) => {
                    let mut cursor = child.walk();
                    for d in child.children_by_field_name("declarator", &mut cursor) {
                        // `static int flag = 0;` declares through an init_declarator.
                        let d = if d.kind() == "init_declarator" {
                            d.child_by_field_name("declarator").unwrap_or(d)
                        } else {
                            d
                        };
                        let name = get_identifier_from_declarator(&d, source);
                        if !name.is_empty() {
                            out.insert(name.to_string());
                        }
                    }
                }
                k if k.starts_with("preproc_") => walk(&child, source, out),
                _ => {}
            }
        }
    }
    let mut out = std::collections::HashSet::new();
    walk(root, source, &mut out);
    out
}

/// Every identifier token in the replacement list of any `#define` in
/// `source` (continuation lines joined), in any arm.
fn define_body_identifiers(source: &str) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let mut lines = source.lines();
    while let Some(line) = lines.next() {
        let mut text = line.to_string();
        while text.ends_with('\\') {
            text.pop();
            match lines.next() {
                Some(next) => text.push_str(next),
                None => break,
            }
        }
        let Some(rest) = text.trim_start().strip_prefix('#') else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix("define") else {
            continue;
        };
        if !rest.starts_with(|c: char| c.is_whitespace()) {
            continue;
        }
        let rest = rest.trim_start();
        let macro_name_len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let body = &rest[macro_name_len..];
        for token in body.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            if token.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
                out.insert(token.to_string());
            }
        }
    }
    out
}

/// Whether `name` appears as a whole token in the replacement list of any
/// `#define` in `source` (continuation lines joined), in any arm.
fn name_in_a_define_body(source: &str, name: &str) -> bool {
    let mut lines = source.lines();
    while let Some(line) = lines.next() {
        let mut text = line.to_string();
        while text.ends_with('\\') {
            text.pop();
            match lines.next() {
                Some(next) => text.push_str(next),
                None => break,
            }
        }
        let Some(rest) = text.trim_start().strip_prefix('#') else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix("define") else {
            continue;
        };
        if !rest.starts_with(|c: char| c.is_whitespace()) {
            continue;
        }
        let rest = rest.trim_start();
        let macro_name_len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let body = &rest[macro_name_len..];
        if contains_token(body, name) {
            return true;
        }
    }
    false
}

/// Whether `text` contains `name` bounded by non-identifier characters.
fn contains_token(text: &str, name: &str) -> bool {
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(off) = text[from..].find(name) {
        let start = from + off;
        let end = start + name.len();
        let before_ok = start == 0 || !is_ident(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_ident(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

/// Whether `id` sits inside the arguments of a call to a name this file
/// defines as a function-like macro, which may write it however its body
/// says (`INC(x)` with `#define INC(v) ((v)++)`).
fn is_function_macro_argument(
    id: &Node,
    source: &str,
    function_macros: &std::collections::HashSet<String>,
) -> bool {
    let mut node = *id;
    while let Some(parent) = node.parent() {
        if parent.kind() == "argument_list" {
            let callee = parent
                .parent()
                .filter(|c| c.kind() == "call_expression")
                .and_then(|c| c.child_by_field_name("function"))
                .filter(|f| f.kind() == "identifier")
                .and_then(|f| f.utf8_text(source.as_bytes()).ok());
            if callee.is_some_and(|c| function_macros.contains(c)) {
                return true;
            }
        }
        if matches!(
            parent.kind(),
            "expression_statement" | "compound_statement" | "function_definition"
        ) {
            break;
        }
        node = parent;
    }
    false
}

/// Whether the expression `id` (looking through parentheses) is written or
/// has its address taken where it stands.
fn is_write_context(id: &Node) -> bool {
    let mut node = *id;
    while let Some(parent) = node.parent() {
        if parent.kind() == "parenthesized_expression" {
            node = parent;
            continue;
        }
        return match parent.kind() {
            "assignment_expression" => parent
                .child_by_field_name("left")
                .is_some_and(|l| l.id() == node.id()),
            "update_expression" => true,
            "pointer_expression" => parent.child(0).is_some_and(|op| op.kind() == "&"),
            _ => false,
        };
    }
    false
}

/// Collect enumerator names + value expressions from any `enum { ... }` in the
/// tree. Enumerators without an explicit value inherit `previous + 1` (default
/// C semantics), seeded at `0` at the start of each enum body.
fn collect_enum_constants(root: &Node, source: &str, defs: &mut Vec<(String, String)>) {
    fn walk(node: &Node, source: &str, defs: &mut Vec<(String, String)>) {
        if node.kind() == "enumerator_list" {
            let mut prev_name: Option<String> = None;
            let mut implicit_idx: i64 = 0;
            for i in 0..node.named_child_count() {
                let Some(e) = node.named_child(i) else {
                    continue;
                };
                if e.kind() != "enumerator" {
                    continue;
                }
                let name = e
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                    .map(str::to_string);
                let value = e
                    .child_by_field_name("value")
                    .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                    .map(str::to_string);

                if let Some(n) = name {
                    let expr = match value {
                        Some(v) => {
                            implicit_idx = 1;
                            prev_name = Some(n.clone());
                            v.trim().to_string()
                        }
                        None => {
                            let expr = match &prev_name {
                                Some(p) => format!("{} + {}", p, implicit_idx),
                                None => implicit_idx.to_string(),
                            };
                            implicit_idx += 1;
                            expr
                        }
                    };
                    defs.push((n, expr));
                }
            }
        }
        for i in 0..node.child_count() {
            if let Some(c) = node.child(i) {
                walk(&c, source, defs);
            }
        }
    }
    walk(root, source, defs);
}

/// Public wrapper around `try_evaluate_text` for callers that already hold
/// the expression as a textual snippet (e.g., substrings of a condition).
pub fn try_evaluate_text_public(text: &str, macros: &MacroConstantMap) -> Option<i64> {
    try_evaluate_text(text, macros)
}

/// Try to evaluate a text string as an integer constant expression.
/// Handles: decimal, hex, octal literals, macro references, simple arithmetic.
fn try_evaluate_text(text: &str, macros: &MacroConstantMap) -> Option<i64> {
    let text = text.trim();
    // Strip trailing C++ line comments (tree-sitter includes them in preproc_arg)
    let text = if let Some(pos) = text.find("//") {
        text[..pos].trim()
    } else {
        text
    };
    if text.is_empty() {
        return None;
    }
    // Strip trailing type suffixes: U, L, UL, LL, ULL (case-insensitive)
    let text = strip_integer_suffix(text);

    // Strip outer parentheses (handles nested like ((10)))
    let mut text = text;
    loop {
        if text.starts_with('(') && text.ends_with(')') {
            let inner = &text[1..text.len() - 1];
            if parens_balanced(inner) {
                text = inner.trim();
                continue;
            }
        }
        break;
    }

    // Try as a literal
    if let Some(val) = parse_integer_literal(text) {
        return Some(val);
    }

    // Try as a macro reference
    if is_c_identifier(text) {
        return macros.get(text).copied();
    }

    // Try sizeof(type_or_expr) — resolve known types exactly, fall back to
    // conservative minimum of 1 for unknown identifiers (sizeof >= 1 always).
    if let Some(inner) = strip_sizeof_call(text) {
        if let Some(sz) = resolve_sizeof_type(inner, macros) {
            return Some(sz);
        }
        // Unknown type/variable: sizeof(x) >= 1 on all platforms. Not for a
        // builtin type whose size the data model leaves open: `sizeof(long)`
        // is not 1 anywhere.
        if is_c_identifier(inner) && !is_builtin_sized_type(inner) {
            return Some(1);
        }
    }

    // Try simple binary expressions: A op B
    // Search for operator from right to left (respecting precedence: +/- before */<<)
    if let Some(val) = try_evaluate_binary_text(text, macros) {
        return Some(val);
    }

    // Try unary negation
    if let Some(rest) = text.strip_prefix('-') {
        let rest = rest.trim();
        if let Some(val) = try_evaluate_text(rest, macros) {
            return val.checked_neg();
        }
    }

    None
}

/// Extract the inner text from a sizeof(...) call in text form.
fn strip_sizeof_call(text: &str) -> Option<&str> {
    let rest = text.strip_prefix("sizeof")?;
    let rest = rest.trim();
    if rest.starts_with('(') && rest.ends_with(')') {
        Some(rest[1..rest.len() - 1].trim())
    } else {
        None
    }
}

/// Try to evaluate a binary expression in text form.
fn try_evaluate_binary_text(text: &str, macros: &MacroConstantMap) -> Option<i64> {
    // Scan for lowest-precedence operators first (+, -), then (*, /), then (<<, >>)
    // Scan right-to-left for left-associativity
    let bytes = text.as_bytes();
    let mut paren_depth = 0i32;

    // Pass 1: + and - (lowest precedence)
    let mut i = bytes.len();
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b')' => paren_depth += 1,
            b'(' => paren_depth -= 1,
            b'+' | b'-' if paren_depth == 0 && i > 0 => {
                // Make sure it's not part of << or >>
                if bytes[i] == b'-' && i > 0 && bytes[i - 1] == b'>' {
                    continue; // -> operator
                }
                let left = text[..i].trim();
                let right = text[i + 1..].trim();
                if !left.is_empty() && !right.is_empty() {
                    let lv = try_evaluate_text(left, macros)?;
                    let rv = try_evaluate_text(right, macros)?;
                    return if bytes[i] == b'+' {
                        lv.checked_add(rv)
                    } else {
                        lv.checked_sub(rv)
                    };
                }
            }
            _ => {}
        }
    }

    // Pass 2: * and /
    paren_depth = 0;
    i = bytes.len();
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b')' => paren_depth += 1,
            b'(' => paren_depth -= 1,
            b'*' | b'/' if paren_depth == 0 && i > 0 => {
                let left = text[..i].trim();
                let right = text[i + 1..].trim();
                if !left.is_empty() && !right.is_empty() {
                    let lv = try_evaluate_text(left, macros)?;
                    let rv = try_evaluate_text(right, macros)?;
                    return if bytes[i] == b'*' {
                        lv.checked_mul(rv)
                    } else if rv == 0 {
                        None
                    } else {
                        Some(lv / rv)
                    };
                }
            }
            _ => {}
        }
    }

    // Pass 3: << and >>
    paren_depth = 0;
    i = bytes.len();
    while i > 1 {
        i -= 1;
        match bytes[i] {
            b')' => paren_depth += 1,
            b'(' => paren_depth -= 1,
            b'<' if paren_depth == 0 && i > 0 && bytes[i - 1] == b'<' => {
                let left = text[..i - 1].trim();
                let right = text[i + 1..].trim();
                if !left.is_empty() && !right.is_empty() {
                    let lv = try_evaluate_text(left, macros)?;
                    let rv = try_evaluate_text(right, macros)?;
                    if !(0..=63).contains(&rv) {
                        return None;
                    }
                    return lv.checked_shl(rv as u32);
                }
                i -= 1; // skip the first <
            }
            b'>' if paren_depth == 0 && i > 0 && bytes[i - 1] == b'>' => {
                let left = text[..i - 1].trim();
                let right = text[i + 1..].trim();
                if !left.is_empty() && !right.is_empty() {
                    let lv = try_evaluate_text(left, macros)?;
                    let rv = try_evaluate_text(right, macros)?;
                    if !(0..=63).contains(&rv) {
                        return None;
                    }
                    return Some(lv >> rv);
                }
                i -= 1;
            }
            _ => {}
        }
    }

    None
}

// ---------------------------------------------------------------------------
// AST-based constant folding
// ---------------------------------------------------------------------------

/// Try to evaluate an AST expression node to an exact integer value.
pub fn try_evaluate_expr(node: &Node, source: &str, macros: &MacroConstantMap) -> Option<i64> {
    match node.kind() {
        "number_literal" => {
            let text = node.utf8_text(source.as_bytes()).ok()?;
            let trimmed = strip_integer_suffix(text.trim());
            parse_integer_literal(trimmed).or_else(|| {
                // Fallback: parse float literals (e.g., 0.0F, 2.0, 1e-40) and truncate to i64.
                // Enables VRA to track float variable assignments for zero-checking.
                let cleaned = trimmed
                    .trim_end_matches('f')
                    .trim_end_matches('F')
                    .trim_end_matches('l')
                    .trim_end_matches('L');
                cleaned.parse::<f64>().ok().map(|f| f as i64)
            })
        }
        "char_literal" => {
            let text = node.utf8_text(source.as_bytes()).ok()?;
            parse_char_literal(text.trim()).map(|c| c as i64)
        }
        "identifier" => {
            let name = node.utf8_text(source.as_bytes()).ok()?;
            macros.get(name).copied()
        }
        "parenthesized_expression" => {
            let inner = node.child(1)?; // skip '('
            try_evaluate_expr(&inner, source, macros)
        }
        "binary_expression" => {
            let left = node.child_by_field_name("left")?;
            let right = node.child_by_field_name("right")?;
            let op = node.child_by_field_name("operator").or_else(|| {
                // tree-sitter C grammar: operator is sometimes an unnamed child
                for i in 0..node.child_count() {
                    if let Some(c) = node.child(i) {
                        let k = c.kind();
                        if matches!(
                            k,
                            "+" | "-"
                                | "*"
                                | "/"
                                | "%"
                                | "<<"
                                | ">>"
                                | "=="
                                | "!="
                                | "<"
                                | ">"
                                | "<="
                                | ">="
                        ) {
                            return Some(c);
                        }
                    }
                }
                None
            })?;
            let op_text = op.utf8_text(source.as_bytes()).ok()?;
            let lv = try_evaluate_expr(&left, source, macros)?;
            let rv = try_evaluate_expr(&right, source, macros)?;
            match op_text {
                "+" => lv.checked_add(rv),
                "-" => lv.checked_sub(rv),
                "*" => lv.checked_mul(rv),
                "/" => {
                    if rv == 0 {
                        None
                    } else {
                        Some(lv / rv)
                    }
                }
                "%" => {
                    if rv == 0 {
                        None
                    } else {
                        Some(lv % rv)
                    }
                }
                "<<" => {
                    if !(0..=63).contains(&rv) {
                        None
                    } else {
                        lv.checked_shl(rv as u32)
                    }
                }
                ">>" => {
                    if !(0..=63).contains(&rv) {
                        None
                    } else {
                        Some(lv >> rv)
                    }
                }
                "==" => Some(if lv == rv { 1 } else { 0 }),
                "!=" => Some(if lv != rv { 1 } else { 0 }),
                "<" => Some(if lv < rv { 1 } else { 0 }),
                ">" => Some(if lv > rv { 1 } else { 0 }),
                "<=" => Some(if lv <= rv { 1 } else { 0 }),
                ">=" => Some(if lv >= rv { 1 } else { 0 }),
                _ => None,
            }
        }
        "unary_expression" => {
            let arg = node.child_by_field_name("argument")?;
            let op = node
                .child_by_field_name("operator")
                .or_else(|| node.child(0))?;
            let op_text = op.utf8_text(source.as_bytes()).ok()?;
            let val = try_evaluate_expr(&arg, source, macros)?;
            match op_text {
                "-" => val.checked_neg(),
                "+" => Some(val),
                "~" => Some(!val),
                "!" => Some(if val == 0 { 1 } else { 0 }),
                _ => None,
            }
        }
        "cast_expression" => {
            // (type)expr — evaluate the inner expression
            let value = node.child_by_field_name("value")?;
            try_evaluate_expr(&value, source, macros)
        }
        "sizeof_expression" => {
            // sizeof(type) or sizeof(expr)
            resolve_sizeof_node(node, source, macros)
        }
        "call_expression" => {
            // Zero-argument calls to known constant functions (e.g., staticReturnsTrue())
            let func = node.child_by_field_name("function")?;
            if func.kind() != "identifier" {
                return None;
            }
            let name = func.utf8_text(source.as_bytes()).ok()?;
            let args = node.child_by_field_name("arguments")?;
            if args.named_child_count() != 0 {
                return None;
            }
            macros.get(name).copied()
        }
        _ => None,
    }
}

/// Resolve a sizeof_expression AST node to a constant value.
fn resolve_sizeof_node(node: &Node, source: &str, macros: &MacroConstantMap) -> Option<i64> {
    resolve_sizeof_type(sizeof_node_type(node, source)?, macros)
}

/// The type a sizeof_expression names: its type_descriptor, or a
/// parenthesized identifier that may be a typedef name (`sizeof(wchar_t)`).
fn sizeof_node_type<'a>(node: &Node, source: &'a str) -> Option<&'a str> {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "type_descriptor" | "primitive_type" | "sized_type_specifier" => {
                    return child.utf8_text(source.as_bytes()).ok();
                }
                "parenthesized_expression" => {
                    if let Some(inner) = child.child(1) {
                        if inner.kind() == "identifier" {
                            return inner.utf8_text(source.as_bytes()).ok();
                        }
                    }
                }
                _ => {}
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Compile-time-constant recognition
// ---------------------------------------------------------------------------

/// An empty name set, so [`ConstantNameSets::none`] can hand out references.
static NO_NAMES: LazyLock<HashSet<String>> = LazyLock::new(HashSet::new);

/// The project-wide names [`is_compile_time_constant_expr`] needs to recognize
/// a constant whose definition is not in the file being analyzed.
#[derive(Clone, Copy)]
pub struct ConstantNameSets<'a> {
    /// Object-like `#define` names — `ProjectContext::defined_macro_names`.
    pub object_macros: &'a HashSet<String>,
    /// Function-like `#define` names — `ProjectContext::function_macros`' keys.
    pub function_macros: &'a HashSet<String>,
    /// Names of real functions whose every `return` expression is itself a
    /// compile-time constant, from `FunctionSummary`'s
    /// `returns_only_compile_time_constants`.
    pub constant_returning_functions: &'a HashSet<String>,
}

impl ConstantNameSets<'static> {
    /// No project context: only `source` itself and the AST are consulted.
    pub fn none() -> Self {
        Self {
            object_macros: &NO_NAMES,
            function_macros: &NO_NAMES,
            constant_returning_functions: &NO_NAMES,
        }
    }
}

/// True if `node` is an expression whose value is fixed at compile time:
/// literals, `sizeof`/`alignof`, macro constants and enumerators (whether or
/// not their value can be folded), function-like macro invocations over such
/// operands, and arithmetic/bitwise combinations of any of those.
///
/// This is deliberately weaker than [`try_evaluate_expr`], which needs an
/// actual integer. A shift by `PAGE_BITS` is no more of an INT34-C hazard
/// than a shift by `12`, but sqc has no preprocessor and the header defining
/// `PAGE_BITS` is frequently one it never parsed — so "did it fold?" is a
/// fact about sqc's include coverage, not about the code under analysis.
///
/// `names` carries the project-wide facts that let a constant defined in
/// another file still be recognized; [`ConstantNameSets::none`] is the
/// single-file answer, where the `#define` scan of `source` and the
/// unresolvable-identifier rule below still apply.
pub fn is_compile_time_constant_expr(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    names: ConstantNameSets,
) -> bool {
    let recurse = |n: &Node| is_compile_time_constant_expr(n, source, macros, names);
    match node.kind() {
        "number_literal" | "char_literal" | "sizeof_expression" | "alignof_expression" => true,
        "parenthesized_expression" => node.named_child(0).is_some_and(|inner| recurse(&inner)),
        "unary_expression" => node
            .child_by_field_name("argument")
            .is_some_and(|arg| recurse(&arg)),
        "binary_expression" => {
            let op = ast_utils::get_binary_operator(node, source).unwrap_or_default();
            if !matches!(
                op,
                "+" | "-" | "*" | "/" | "%" | "<<" | ">>" | "&" | "|" | "^"
            ) {
                return false;
            }
            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return false;
            };
            recurse(&left) && recurse(&right)
        }
        "conditional_expression" => (0..node.named_child_count())
            .filter_map(|i| node.named_child(i))
            .all(|c| recurse(&c)),
        "cast_expression" => node
            .child_by_field_name("value")
            .is_some_and(|v| recurse(&v)),
        // `MASK(n)`, `CBn_MAIRm_ATTR_SHIFT(id)` — a function-like macro over
        // constant arguments is itself a constant, as is a call to a real
        // function whose every `return` is one (seL4's `pageBitsForSize()`).
        // A call to anything else is not: `x << get_amount()` stays open.
        "call_expression" => {
            let Some(callee) = node.child_by_field_name("function") else {
                return false;
            };
            if callee.kind() != "identifier" {
                return false;
            }
            let name = ast_utils::get_node_text(&callee, source);
            if names.constant_returning_functions.contains(name) {
                // The callee's own returns were already checked; its
                // ARGUMENTS are irrelevant, since no return depends on them.
                return true;
            }
            if !names.function_macros.contains(name)
                && !ast_utils::is_defined_macro_name(name, source)
            {
                return false;
            }
            node.child_by_field_name("arguments")
                .map(|args| {
                    (0..args.named_child_count())
                        .filter_map(|i| args.named_child(i))
                        .all(|a| recurse(&a))
                })
                .unwrap_or(false)
        }
        "identifier" => {
            let name = ast_utils::get_node_text(node, source);

            // A `#define` or enumerator sqc did fold.
            if macros.contains_key(name) {
                return true;
            }
            // A `#define` sqc saw but could not fold (its replacement names
            // something from a header outside the scan).
            if names.object_macros.contains(name) || ast_utils::is_defined_macro_name(name, source)
            {
                return true;
            }
            // No binding anywhere sqc looked: not a local, not a parameter,
            // not a file-scope declaration. C requires every identifier to be
            // declared before use, so this one is a macro or an enumerator
            // from a header that wasn't parsed — seL4's `seL4_PageBits`
            // (generated per architecture) and `ARMSectionBits` (an
            // enumerator in a header outside the scan root) both land here.
            // It cannot be a local whose range we simply failed to compute,
            // which is the case that matters.
            ast_utils::resolve_identifier_binding(node, name, source).is_none()
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Range evaluation
// ---------------------------------------------------------------------------

/// Evaluate an AST expression node to a value range.
/// Falls back to `var_ranges` for identifiers not in macros.
pub fn try_evaluate_range(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    var_ranges: &VarRangeMap,
) -> Option<ValueRange> {
    try_evaluate_range_inner(node, source, macros, var_ranges, None)
}

/// [`try_evaluate_range`], additionally expanding invocations of the
/// function-like macros in `function_macros` before giving up on them.
///
/// Split from the plain entry point rather than folded into it because the
/// macro table is a *project* fact (`ProjectContext::function_macros`) that
/// most callers do not hold, and because expanding costs a re-parse of the
/// replacement list. A caller that has the table gets `MASK(3)`,
/// `LINEBITS(s)` and `IDR0_NUMSIDB_VAL(reg & IDR0_NUMSIDB)` bounded like the
/// expressions they stand for; every other caller is unaffected.
pub fn try_evaluate_range_expanding(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    var_ranges: &VarRangeMap,
    function_macros: &HashMap<String, FunctionMacro>,
) -> Option<ValueRange> {
    try_evaluate_range_inner(node, source, macros, var_ranges, Some(function_macros))
}

fn try_evaluate_range_inner(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    var_ranges: &VarRangeMap,
    fmacros: Option<&HashMap<String, FunctionMacro>>,
) -> Option<ValueRange> {
    // First try exact evaluation
    if let Some(val) = try_evaluate_expr(node, source, macros) {
        return Some(ValueRange::exact(val));
    }

    match node.kind() {
        "identifier" => {
            let name = node.utf8_text(source.as_bytes()).ok()?;
            if let Some(&val) = macros.get(name) {
                return Some(ValueRange::exact(val));
            }
            var_ranges.get(name).copied()
        }
        "parenthesized_expression" => {
            let inner = node.child(1)?;
            try_evaluate_range_inner(&inner, source, macros, var_ranges, fmacros)
        }
        "binary_expression" => {
            let left = node.child_by_field_name("left")?;
            let right = node.child_by_field_name("right")?;
            let op = node.child_by_field_name("operator").or_else(|| {
                for i in 0..node.child_count() {
                    if let Some(c) = node.child(i) {
                        let k = c.kind();
                        if matches!(k, "+" | "-" | "*" | "/" | "%" | "<<" | ">>" | "&") {
                            return Some(c);
                        }
                    }
                }
                None
            })?;
            let op_text = op.utf8_text(source.as_bytes()).ok()?;

            // Bitwise AND: `expr & MASK` or `MASK & expr`.
            // For a non-negative constant mask M, the result is always in [0, M]
            // regardless of the other operand — even if that operand's range
            // cannot be computed (e.g. overflows in arithmetic).  This lets VRA
            // prove that `(SHA256_WORD_BITS - b) & SHA256_WORD_MASK` ∈ [0, 31]
            // when SHA256_WORD_MASK = 31.
            if op_text == "&" {
                let lr = try_evaluate_range_inner(&left, source, macros, var_ranges, fmacros);
                let rr = try_evaluate_range_inner(&right, source, macros, var_ranges, fmacros);
                return match (lr, rr) {
                    (Some(l), Some(r)) => l.bitand(&r),
                    // One side unknown, other is a known non-negative constant mask.
                    (None, Some(r)) if r.min == r.max && r.min >= 0 => {
                        Some(ValueRange::new(0, r.min))
                    }
                    (Some(l), None) if l.min == l.max && l.min >= 0 => {
                        Some(ValueRange::new(0, l.min))
                    }
                    _ => None,
                };
            }

            let lr = try_evaluate_range_inner(&left, source, macros, var_ranges, fmacros)?;
            let rr = try_evaluate_range_inner(&right, source, macros, var_ranges, fmacros)?;
            match op_text {
                "+" => lr.add(&rr),
                "-" => lr.sub(&rr),
                "*" => lr.mul(&rr),
                "/" => lr.div(&rr),
                "%" => lr.rem(&rr),
                "<<" => lr.shl(&rr),
                ">>" => lr.shr(&rr),
                _ => None,
            }
        }
        // `x += 1` evaluates to the value stored, so its range is that of the
        // equivalent binary expression. Without this arm a compound assignment
        // yielded no range at all, which is what hid `value1 += 1` with
        // `value1 == INT_MAX` from the definite-overflow check. A plain `=`
        // evaluates to its RHS.
        "assignment_expression" => {
            let left = node.child_by_field_name("left")?;
            let right = node.child_by_field_name("right")?;
            let rr = try_evaluate_range(&right, source, macros, var_ranges)?;
            let op_text = assignment_operator_text(node, source);
            if op_text == "=" {
                return Some(rr);
            }
            let lr = try_evaluate_range(&left, source, macros, var_ranges)?;
            match op_text.as_str() {
                "+=" => lr.add(&rr),
                "-=" => lr.sub(&rr),
                "*=" => lr.mul(&rr),
                "/=" => lr.div(&rr),
                "%=" => lr.rem(&rr),
                "<<=" => lr.shl(&rr),
                "&=" => lr.bitand(&rr),
                _ => None,
            }
        }
        "unary_expression" => {
            let arg = node.child_by_field_name("argument")?;
            let op = node
                .child_by_field_name("operator")
                .or_else(|| node.child(0))?;
            let op_text = op.utf8_text(source.as_bytes()).ok()?;
            let r = try_evaluate_range_inner(&arg, source, macros, var_ranges, fmacros)?;
            match op_text {
                "-" => Some(ValueRange::new(r.max.checked_neg()?, r.min.checked_neg()?)),
                "+" => Some(r),
                _ => None,
            }
        }
        "cast_expression" => {
            let value = node.child_by_field_name("value")?;
            try_evaluate_range_inner(&value, source, macros, var_ranges, fmacros)
        }
        "sizeof_expression" => {
            let type_text = sizeof_node_type(node, source)?;
            resolve_sizeof_type(type_text, macros)
                .map(ValueRange::exact)
                .or_else(|| sizeof_type_bounds(type_text))
        }
        // A function-like macro invocation parses as a call. When the caller
        // supplied the macro table, expand it and bound the replacement list
        // instead of treating it as an opaque call. Failing that, a standard
        // function's return value is bounded by its own contract.
        "call_expression" => fmacros
            .and_then(|fm| range_from_macro_invocation(node, source, macros, var_ranges, fm))
            .or_else(|| {
                let callee = node.child_by_field_name("function")?;
                if callee.kind() != "identifier" {
                    return None;
                }
                contract_return_range(callee.utf8_text(source.as_bytes()).ok()?)
            }),
        // Struct member access: obj.field or obj->field.
        // Try to bound by the declared type of the field by searching the source for
        // `uint8_t fieldName` / `uint16_t fieldName` etc. in struct definitions.
        "field_expression" => {
            if let Some(field_node) = node.child_by_field_name("field") {
                let field_name = field_node.utf8_text(source.as_bytes()).ok()?;
                bound_from_field_type(field_name, source)
            } else {
                None
            }
        }
        "update_expression" => {
            // data++ / data-- / ++data / --data
            let arg = node.child_by_field_name("argument")?;
            let op = node.child_by_field_name("operator").or_else(|| {
                // Operator may be first or last child depending on prefix/postfix
                for i in 0..node.child_count() {
                    if let Some(c) = node.child(i) {
                        let k = c.kind();
                        if k == "++" || k == "--" {
                            return Some(c);
                        }
                    }
                }
                None
            })?;
            let op_text = op.utf8_text(source.as_bytes()).ok()?;
            let r = try_evaluate_range_inner(&arg, source, macros, var_ranges, fmacros)?;
            let one = ValueRange::exact(1);
            match op_text {
                "++" => r.add(&one),
                "--" => r.sub(&one),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The range a standard library function's return value is confined to by
/// its own specification -- what the language guarantees about a call before
/// any code around it is read.
///
/// `rand()` returns an `int` in `[0, RAND_MAX]` (C11 7.22.2.1) and `random()`
/// a `long` in `[0, 2^31 - 1]` (POSIX), so `rand() % 60` is `[0, 59]` and
/// `1 + rand() % 60` cannot overflow, yet both were opaque here: INT10-C
/// reported the modulo's dividend as possibly negative and INT32-C the sum as
/// unbounded -- 128 of one valkey batch's 158 INT10-C findings were this one
/// shape. `RAND_MAX` itself is implementation-defined, so the
/// bound used is `INT_MAX`, the largest it can be; a range must never be
/// narrower than the truth.
///
/// Only functions whose range the standard fixes belong here. A project's
/// own PRNG wrapper is not one of them: `randomULong()` reaches this through
/// the macro table when it is a macro, and a wrapper FUNCTION stays opaque
/// rather than guessed at from its name. The provenance list in
/// `std_functions::is_full_range_return_function` deliberately still names these
/// functions: a range says how large the value can be, provenance says the
/// program does not control it, and `1 + rand()` with no `%` really can
/// overflow.
pub fn contract_return_range(name: &str) -> Option<ValueRange> {
    match name {
        // C11 7.22.2.1: `0 <= rand() <= RAND_MAX`, RAND_MAX an int.
        "rand" | "rand_r" => Some(ValueRange::new(0, i32::MAX as i64)),
        // POSIX random()/lrand48()/nrand48(): "in the range [0, 2^31)".
        "random" | "lrand48" | "nrand48" => Some(ValueRange::new(0, (1i64 << 31) - 1)),
        // arc4random() (BSD, glibc >= 2.36): a uint32_t.
        "arc4random" => Some(ValueRange::new(0, u32::MAX as i64)),
        _ => None,
    }
}

/// Bound a function-like macro invocation by the expression it expands to.
///
/// Macro expansion is textual substitution, so an identifier that survives
/// into the replacement list still names whatever it named at the invocation
/// site — which is why `var_ranges` stays the right environment for the
/// expansion, and why `LINEBITS(s)` bounds exactly as the `((s) & MASK(3)) + 4`
/// a reader sees when they follow the `#define`.
///
/// [`macro_expand::expand_invocation`] rescans its own output, so a nested
/// `MASK(3)` is already gone by the time the expansion gets here and the
/// expansion is evaluated with no macro table of its own. That is also what
/// bounds the work: whatever the expander declined to expand -- a
/// self-referential macro, an arity mismatch -- stays an opaque call and
/// simply fails to evaluate, rather than being handed back to the expander
/// for another round.
fn range_from_macro_invocation(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    var_ranges: &VarRangeMap,
    fmacros: &HashMap<String, FunctionMacro>,
) -> Option<ValueRange> {
    let callee = node.child_by_field_name("function")?;
    if callee.kind() != "identifier" {
        return None;
    }
    let name = callee.utf8_text(source.as_bytes()).ok()?;
    if !fmacros.contains_key(name) {
        return None;
    }
    let arg_list = node.child_by_field_name("arguments")?;
    let mut cursor = arg_list.walk();
    let args: Vec<String> = arg_list
        .named_children(&mut cursor)
        .map(|arg| arg.utf8_text(source.as_bytes()).unwrap_or("").to_string())
        .collect();
    let expanded = macro_expand::expand_invocation(fmacros, name, &args)?;
    evaluate_snippet_range(&expanded, macros, var_ranges)
}

/// Parse `text` as a standalone expression and evaluate its range.
///
/// Wrapped in an initializer so tree-sitter parses it as an expression rather
/// than guessing at a declaration; a replacement list that does not stand
/// alone as one parses to `ERROR` and simply fails to evaluate.
fn evaluate_snippet_range(
    text: &str,
    macros: &MacroConstantMap,
    var_ranges: &VarRangeMap,
) -> Option<ValueRange> {
    let snippet = format!("int _sqc_macro_expansion_ = ({text});");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&crate::parser::c_language()).ok()?;
    let tree = parser.parse(&snippet, None)?;
    let declarator = tree
        .root_node()
        .named_child(0)?
        .child_by_field_name("declarator")?;
    let value = declarator.child_by_field_name("value")?;
    try_evaluate_range_inner(&value, &snippet, macros, var_ranges, None)
}

/// Search the source for a struct field declaration matching `field_name` and
/// return a conservative `ValueRange` based on the declared type.
/// This allows VRA to bound struct field accesses by their declared type width
/// (e.g., `uint8_t length` → [0, 255]) without full struct-type resolution.
fn bound_from_field_type(field_name: &str, source: &str) -> Option<ValueRange> {
    // Narrow integer types with known bounds
    const TYPE_BOUNDS: &[(&str, i64)] = &[
        ("uint8_t", 255),
        ("int8_t", 127),
        ("uint16_t", 65535),
        ("int16_t", 32767),
    ];
    for line in source.lines() {
        let trimmed = line.trim();
        // Look for lines like `uint8_t fieldName;` or `uint8_t fieldName,`
        // within struct definitions. Simple text match — false positives are
        // suppressive (safe), false negatives leave the violation in place.
        for (type_name, max_val) in TYPE_BOUNDS {
            if trimmed.contains(type_name) && trimmed.contains(field_name) {
                // Verify the field name appears after the type (rough word-boundary check)
                if let Some(type_pos) = trimmed.find(type_name) {
                    let after_type = &trimmed[type_pos + type_name.len()..];
                    if after_type.contains(field_name) {
                        let min_val = if type_name.starts_with('u') {
                            0
                        } else {
                            -(*max_val) - 1
                        };
                        return Some(ValueRange::new(min_val, *max_val));
                    }
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Loop-bound extraction
// ---------------------------------------------------------------------------

/// Extract value ranges for variables bounded by enclosing loop conditions.
/// Walks AST ancestors looking for `for`/`while` statements and extracts
/// `var < BOUND` or `var <= BOUND` patterns.
pub fn extract_loop_var_ranges(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
) -> VarRangeMap {
    let mut ranges = VarRangeMap::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "while_statement" | "do_statement" => {
                if let Some(condition) = parent.child_by_field_name("condition") {
                    extract_bound_from_condition(&condition, source, macros, &mut ranges);
                }
            }
            "for_statement" => {
                // Extract upper bound from condition
                if let Some(condition) = parent.child_by_field_name("condition") {
                    extract_bound_from_condition(&condition, source, macros, &mut ranges);
                }
                // Extract lower bound from initializer
                if let Some(initializer) = parent.child_by_field_name("initializer") {
                    extract_init_from_for(&initializer, source, macros, &mut ranges);
                }
            }
            "function_definition" | "translation_unit" => break,
            _ => {}
        }
        current = parent.parent();
    }
    ranges
}

/// Extract variable bounds from a loop condition expression.
/// Handles: `var < expr`, `var <= expr`, `expr > var`, `expr >= var`.
/// Also handles compound `&&` conditions by extracting bounds from each sub-expression.
fn extract_bound_from_condition(
    condition: &Node,
    source: &str,
    macros: &MacroConstantMap,
    ranges: &mut VarRangeMap,
) {
    // Unwrap parenthesized_expression
    let cond = if condition.kind() == "parenthesized_expression" {
        condition.child(1).unwrap_or(*condition)
    } else {
        *condition
    };

    if cond.kind() != "binary_expression" {
        return;
    }

    // Handle compound && conditions: extract bounds from each side
    let op = get_operator_text(&cond, source);
    if op == "&&" {
        if let Some(left) = cond.child_by_field_name("left") {
            extract_bound_from_condition(&left, source, macros, ranges);
        }
        if let Some(right) = cond.child_by_field_name("right") {
            extract_bound_from_condition(&right, source, macros, ranges);
        }
        return;
    }
    let left = match cond.child_by_field_name("left") {
        Some(n) => n,
        None => return,
    };
    let right = match cond.child_by_field_name("right") {
        Some(n) => n,
        None => return,
    };

    let op = get_operator_text(&cond, source);

    match op.as_str() {
        "<"
            // var < BOUND → var in [0, BOUND-1] (assuming non-negative loop counter)
            if left.kind() == "identifier" => {
                if let Some(bound) = try_evaluate_expr(&right, source, macros) {
                    let var_name = left.utf8_text(source.as_bytes()).unwrap_or("");
                    if !var_name.is_empty() {
                        let entry = ranges
                            .entry(var_name.to_string())
                            .or_insert(ValueRange::new(0, bound - 1));
                        // Tighten upper bound if this condition is more restrictive
                        if bound - 1 < entry.max {
                            entry.max = bound - 1;
                        }
                    }
                }
            }
        "<="
            if left.kind() == "identifier" => {
                if let Some(bound) = try_evaluate_expr(&right, source, macros) {
                    let var_name = left.utf8_text(source.as_bytes()).unwrap_or("");
                    if !var_name.is_empty() {
                        let entry = ranges
                            .entry(var_name.to_string())
                            .or_insert(ValueRange::new(0, bound));
                        if bound < entry.max {
                            entry.max = bound;
                        }
                    }
                }
            }
        ">"
            // BOUND > var → same as var < BOUND
            if right.kind() == "identifier" => {
                if let Some(bound) = try_evaluate_expr(&left, source, macros) {
                    let var_name = right.utf8_text(source.as_bytes()).unwrap_or("");
                    if !var_name.is_empty() {
                        let entry = ranges
                            .entry(var_name.to_string())
                            .or_insert(ValueRange::new(0, bound - 1));
                        if bound - 1 < entry.max {
                            entry.max = bound - 1;
                        }
                    }
                }
            }
        ">="
            if right.kind() == "identifier" => {
                if let Some(bound) = try_evaluate_expr(&left, source, macros) {
                    let var_name = right.utf8_text(source.as_bytes()).unwrap_or("");
                    if !var_name.is_empty() {
                        let entry = ranges
                            .entry(var_name.to_string())
                            .or_insert(ValueRange::new(0, bound));
                        if bound < entry.max {
                            entry.max = bound;
                        }
                    }
                }
            }
        _ => {}
    }
}

/// Extract initializer value from a for-loop init clause.
fn extract_init_from_for(
    init: &Node,
    source: &str,
    macros: &MacroConstantMap,
    ranges: &mut VarRangeMap,
) {
    // Handle `int var = expr` (declaration) or `var = expr` (assignment_expression)
    match init.kind() {
        "declaration" => {
            for i in 0..init.child_count() {
                if let Some(child) = init.child(i) {
                    if child.kind() == "init_declarator" {
                        if let (Some(declarator), Some(value)) = (
                            child.child_by_field_name("declarator"),
                            child.child_by_field_name("value"),
                        ) {
                            let var_name = declarator
                                .utf8_text(source.as_bytes())
                                .unwrap_or("")
                                .to_string();
                            if !var_name.is_empty() {
                                if let Some(val) = try_evaluate_expr(&value, source, macros) {
                                    if let Some(range) = ranges.get_mut(&var_name) {
                                        range.min = val;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        "assignment_expression" => {
            if let (Some(left), Some(right)) = (
                init.child_by_field_name("left"),
                init.child_by_field_name("right"),
            ) {
                if left.kind() == "identifier" {
                    let var_name = left.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                    if !var_name.is_empty() {
                        if let Some(val) = try_evaluate_expr(&right, source, macros) {
                            if let Some(range) = ranges.get_mut(&var_name) {
                                range.min = val;
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Local variable resolution
// ---------------------------------------------------------------------------

/// Scan backward in the enclosing compound_statement for assignments to `var_name`
/// and try to evaluate the RHS as a range.
pub fn resolve_local_var_range(
    var_name: &str,
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    loop_ranges: &VarRangeMap,
) -> Option<ValueRange> {
    resolve_local_var_range_depth(var_name, node, source, macros, loop_ranges, None, 0)
}

/// [`resolve_local_var_range`], evaluating each candidate RHS with
/// [`try_evaluate_range_expanding`] so a local initialised from a
/// function-like macro (`int lbits = LINEBITS(s);`) is bounded by what that
/// macro expands to.
pub fn resolve_local_var_range_expanding(
    var_name: &str,
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    loop_ranges: &VarRangeMap,
    function_macros: &HashMap<String, FunctionMacro>,
) -> Option<ValueRange> {
    resolve_local_var_range_depth(
        var_name,
        node,
        source,
        macros,
        loop_ranges,
        Some(function_macros),
        0,
    )
}

fn resolve_local_var_range_depth(
    var_name: &str,
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    loop_ranges: &VarRangeMap,
    fmacros: Option<&HashMap<String, FunctionMacro>>,
    depth: u32,
) -> Option<ValueRange> {
    // Find the enclosing compound_statement (function body or block)
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "compound_statement" {
            // Scan statements before our node, keeping the LAST assignment
            // (not the first) since later assignments overwrite earlier ones.
            // If the last modification is unevaluable (e.g., data = rand(),
            // or fscanf(stdin, "%d", &data)), return None so callers don't
            // use a stale range from an earlier assignment.
            let node_start = node.start_byte();
            let mut last_range: Option<ValueRange> = None;
            let mut invalidated = false;
            for i in 0..parent.child_count() {
                if let Some(stmt) = parent.child(i) {
                    if stmt.start_byte() >= node_start {
                        break;
                    }
                    // Check for evaluable assignment (data = CONST or data = expr)
                    if let Some(range) = check_stmt_for_var_assignment(
                        &stmt,
                        var_name,
                        source,
                        macros,
                        loop_ranges,
                        fmacros,
                        depth,
                    ) {
                        last_range = Some(range);
                        invalidated = false;
                    } else if stmt_modifies_var(&stmt, var_name, source) {
                        // Assignment found but RHS unevaluable (e.g., rand()),
                        // or variable modified through pointer (e.g., fscanf(&var))
                        last_range = None;
                        invalidated = true;
                    }
                }
            }
            if invalidated {
                return None;
            }
            if last_range.is_some() {
                return last_range;
            }
        }
        if parent.kind() == "function_definition" {
            break;
        }
        current = parent.parent();
    }
    None
}

/// Check a single statement for an assignment to `var_name` and return its range.
/// When the RHS is a bare identifier and `depth < 3`, recursively resolves the
/// identifier's value so that copy chains like `int dataCopy = data; int data = dataCopy`
/// are traced back to their original literal source.
fn check_stmt_for_var_assignment(
    stmt: &Node,
    var_name: &str,
    source: &str,
    macros: &MacroConstantMap,
    loop_ranges: &VarRangeMap,
    fmacros: Option<&HashMap<String, FunctionMacro>>,
    depth: u32,
) -> Option<ValueRange> {
    match stmt.kind() {
        "expression_statement" => check_assignment_expr_for_var(
            stmt,
            var_name,
            source,
            macros,
            loop_ranges,
            fmacros,
            depth,
        ),
        "declaration" => check_init_declarator_for_var(
            stmt,
            var_name,
            source,
            macros,
            loop_ranges,
            fmacros,
            depth,
        ),
        // Control-flow wrappers: scan the compound body for evaluable assignments.
        // Returns the last evaluable assignment found, or None if the body contains
        // any unevaluable modification (e.g., fscanf(&var)) — which triggers the
        // caller's `stmt_modifies_var` fallback and marks the variable as invalidated.
        // This handles goodG2B patterns like `for(h=0;h<1;h++) { data = 2; }` where
        // stmt_modifies_var correctly recognizes the modification but the loop body
        // contains only a simple literal assignment.
        "for_statement" | "while_statement" | "do_statement" | "if_statement" => {
            check_control_flow_body_for_var(
                stmt,
                var_name,
                source,
                macros,
                loop_ranges,
                fmacros,
                depth,
            )
        }
        _ => None,
    }
}

/// Resolve a candidate RHS expression against a value-tracked variable:
/// evaluate it directly, or (up to depth 3) recurse through a same-named
/// identifier RHS to resolve *its* assigned range.
fn resolve_var_rhs(
    rhs: &Node,
    stmt: &Node,
    source: &str,
    macros: &MacroConstantMap,
    loop_ranges: &VarRangeMap,
    fmacros: Option<&HashMap<String, FunctionMacro>>,
    depth: u32,
) -> Option<ValueRange> {
    if let Some(r) = try_evaluate_range_inner(rhs, source, macros, loop_ranges, fmacros) {
        return Some(r);
    }
    if rhs.kind() == "identifier" && depth < 3 {
        let rhs_name = rhs.utf8_text(source.as_bytes()).unwrap_or("");
        return resolve_local_var_range_depth(
            rhs_name,
            stmt,
            source,
            macros,
            loop_ranges,
            fmacros,
            depth + 1,
        );
    }
    None
}

/// `"expression_statement"` case of [`check_stmt_for_var_assignment`]: find
/// an `assignment_expression` whose LHS is `var_name` and resolve its RHS.
///
/// Only a plain `=` states the variable's new value. A compound assignment
/// (`msbs -= 8`, `x <<= 1`) says how the value *changes*, so reading its RHS
/// as the new range is simply wrong -- it would put sqlite's `msbs`, which
/// counts 48, 40, ... 0 down a loop, at a flat 8. Declining it here hands the
/// statement to the caller's `stmt_modifies_var` check, which invalidates the
/// variable rather than letting a stale earlier range stand.
fn check_assignment_expr_for_var(
    stmt: &Node,
    var_name: &str,
    source: &str,
    macros: &MacroConstantMap,
    loop_ranges: &VarRangeMap,
    fmacros: Option<&HashMap<String, FunctionMacro>>,
    depth: u32,
) -> Option<ValueRange> {
    for i in 0..stmt.child_count() {
        let child = stmt.child(i)?;
        if child.kind() != "assignment_expression" {
            continue;
        }
        let (Some(left), Some(right)) = (
            child.child_by_field_name("left"),
            child.child_by_field_name("right"),
        ) else {
            continue;
        };
        if left.kind() != "identifier" {
            continue;
        }
        let plain_assignment = child
            .child_by_field_name("operator")
            .and_then(|op| op.utf8_text(source.as_bytes()).ok())
            .is_some_and(|op| op == "=");
        if !plain_assignment {
            continue;
        }
        let name = left.utf8_text(source.as_bytes()).unwrap_or("");
        if name == var_name {
            return resolve_var_rhs(&right, stmt, source, macros, loop_ranges, fmacros, depth);
        }
    }
    None
}

/// `"declaration"` case of [`check_stmt_for_var_assignment`]: find an
/// `init_declarator` declaring `var_name` and resolve its init value.
fn check_init_declarator_for_var(
    stmt: &Node,
    var_name: &str,
    source: &str,
    macros: &MacroConstantMap,
    loop_ranges: &VarRangeMap,
    fmacros: Option<&HashMap<String, FunctionMacro>>,
    depth: u32,
) -> Option<ValueRange> {
    for i in 0..stmt.child_count() {
        let child = stmt.child(i)?;
        if child.kind() != "init_declarator" {
            continue;
        }
        let (Some(declarator), Some(value)) = (
            child.child_by_field_name("declarator"),
            child.child_by_field_name("value"),
        ) else {
            continue;
        };
        let name = extract_leaf_identifier(&declarator, source);
        if name == var_name {
            return resolve_var_rhs(&value, stmt, source, macros, loop_ranges, fmacros, depth);
        }
    }
    None
}

/// Control-flow-wrapper case of [`check_stmt_for_var_assignment`]: scan a
/// `for`/`while`/`do`/`if` statement's compound body for evaluable
/// assignments to `var_name`, bailing to `None` on an inner-scope shadow or
/// an unevaluable modification.
fn check_control_flow_body_for_var(
    stmt: &Node,
    var_name: &str,
    source: &str,
    macros: &MacroConstantMap,
    loop_ranges: &VarRangeMap,
    fmacros: Option<&HashMap<String, FunctionMacro>>,
    depth: u32,
) -> Option<ValueRange> {
    for i in 0..stmt.child_count() {
        let child = stmt.child(i)?;
        if child.kind() != "compound_statement" {
            continue;
        }
        if compound_declares_var(&child, var_name, source) {
            return None; // inner-scope shadow — don't evaluate
        }
        let mut last_range: Option<ValueRange> = None;
        for j in 0..child.child_count() {
            let Some(inner) = child.child(j) else {
                continue;
            };
            if let Some(r) = check_stmt_for_var_assignment(
                &inner,
                var_name,
                source,
                macros,
                loop_ranges,
                fmacros,
                depth,
            ) {
                last_range = Some(r);
            } else if stmt_modifies_var(&inner, var_name, source) {
                return None; // unevaluable modification in body
            }
        }
        return last_range;
    }
    None
}

/// Check if a statement modifies `var_name` in a way that `check_stmt_for_var_assignment`
/// couldn't evaluate. Covers:
/// - Direct assignment with unevaluable RHS: `var = rand();`, `var = RAND32();`
/// - Pointer modification via function call: `fscanf(stdin, "%d", &var);`
/// - Modifications inside control flow wrappers: `if(1) { fscanf(..., &var); }`
fn stmt_modifies_var(stmt: &Node, var_name: &str, source: &str) -> bool {
    match stmt.kind() {
        "expression_statement" => {
            for i in 0..stmt.child_count() {
                if let Some(child) = stmt.child(i) {
                    // Direct assignment: var = <unevaluable>
                    if child.kind() == "assignment_expression" {
                        if let Some(left) = child.child_by_field_name("left") {
                            if left.kind() == "identifier" {
                                let name = left.utf8_text(source.as_bytes()).unwrap_or("");
                                if name == var_name {
                                    return true;
                                }
                            }
                        }
                    }
                    // Pointer modification: func(..., &var, ...)
                    if child.kind() == "call_expression" {
                        if call_takes_address_of(&child, var_name, source) {
                            return true;
                        }
                    }
                }
            }
        }
        "declaration" => {
            for i in 0..stmt.child_count() {
                if let Some(child) = stmt.child(i) {
                    if child.kind() == "init_declarator" {
                        if let Some(declarator) = child.child_by_field_name("declarator") {
                            let name = extract_leaf_identifier(&declarator, source);
                            if name == var_name && child.child_by_field_name("value").is_some() {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        // Control-flow wrappers: recurse into bodies so that tainted assignments inside
        // if(1)/while/for blocks are not invisible to the backward scan. This prevents
        // `resolve_local_var_range` from returning a stale pre-taint range.
        // We skip compound_statement bodies that declare var_name (inner scope shadow)
        // so that `int data = dataCopy;` blocks don't invalidate the outer `data`.
        "if_statement" | "while_statement" | "for_statement" | "do_statement"
        | "switch_statement" => {
            for i in 0..stmt.child_count() {
                if let Some(child) = stmt.child(i) {
                    match child.kind() {
                        // Skip if this block declares var_name (shadow)
                        "compound_statement"
                            if !compound_declares_var(&child, var_name, source) =>
                        {
                            for j in 0..child.child_count() {
                                if let Some(inner) = child.child(j) {
                                    if stmt_modifies_var(&inner, var_name, source) {
                                        return true;
                                    }
                                }
                            }
                        }
                        "compound_statement" => {}
                        // Single-statement bodies (no braces): check directly
                        "expression_statement" | "declaration"
                            if stmt_modifies_var(&child, var_name, source) =>
                        {
                            return true;
                        }
                        "expression_statement" | "declaration" => {}
                        // Nested control flow (else-if chains, etc.)
                        "if_statement" | "while_statement" | "for_statement" | "do_statement"
                        | "switch_statement"
                            if stmt_modifies_var(&child, var_name, source) =>
                        {
                            return true;
                        }
                        "if_statement" | "while_statement" | "for_statement" | "do_statement"
                        | "switch_statement" => {}
                        // switch case labels and goto targets
                        "case_statement" | "default_statement" | "labeled_statement" => {
                            for j in 0..child.child_count() {
                                if let Some(inner) = child.child(j) {
                                    if stmt_modifies_var(&inner, var_name, source) {
                                        return true;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        _ => {}
    }
    false
}

/// Returns true if the compound_statement has a direct-child declaration of `var_name`,
/// meaning any assignments to `var_name` within it target an inner-scope shadow variable.
fn compound_declares_var(compound: &Node, var_name: &str, source: &str) -> bool {
    for i in 0..compound.child_count() {
        if let Some(stmt) = compound.child(i) {
            if stmt.kind() == "declaration" {
                for j in 0..stmt.child_count() {
                    if let Some(child) = stmt.child(j) {
                        if child.kind() == "init_declarator" {
                            if let Some(decl) = child.child_by_field_name("declarator") {
                                if extract_leaf_identifier(&decl, source) == var_name {
                                    return true;
                                }
                            }
                        } else if child.kind() == "identifier" {
                            if child.utf8_text(source.as_bytes()).unwrap_or("") == var_name {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

/// Check if a call expression passes `&var_name` as an argument.
fn call_takes_address_of(call: &Node, var_name: &str, source: &str) -> bool {
    if let Some(args) = call.child_by_field_name("arguments") {
        for i in 0..args.child_count() {
            if let Some(arg) = args.child(i) {
                // Match &var_name (unary_expression with & operator)
                if arg.kind() == "pointer_expression" || arg.kind() == "unary_expression" {
                    let text = arg.utf8_text(source.as_bytes()).unwrap_or("");
                    if text == format!("&{}", var_name) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Extract leaf identifier from a declarator chain (pointer_declarator → identifier).
fn extract_leaf_identifier(node: &Node, source: &str) -> String {
    match node.kind() {
        "identifier" => node.utf8_text(source.as_bytes()).unwrap_or("").to_string(),
        "pointer_declarator" | "array_declarator" => {
            if let Some(inner) = node.child_by_field_name("declarator") {
                extract_leaf_identifier(&inner, source)
            } else {
                String::new()
            }
        }
        _ => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "identifier" {
                        return child.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                    }
                }
            }
            String::new()
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience functions for rule integration
// ---------------------------------------------------------------------------

/// Returns true if the expression provably fits in a signed integer of the given bit width.
/// Combines macro constants, loop-bound extraction, and local variable resolution.
///
/// For left shift operations, also verifies the left operand is non-negative
/// (shifting negative values is UB in C regardless of result).
pub fn expression_fits_in_signed(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    bits: u32,
) -> bool {
    let loop_ranges = extract_loop_var_ranges(node, source, macros);
    let mut var_ranges = loop_ranges.clone();
    resolve_identifiers_in_expr(node, source, macros, &loop_ranges, &mut var_ranges);

    if let Some(range) = try_evaluate_range(node, source, macros, &var_ranges) {
        // For left shift: shifting negative values is UB even if result fits
        if node.kind() == "binary_expression" {
            if is_shift_operator(node, source) && range.min < 0 {
                return false;
            }
            // Also check if left operand of shift is negative
            if is_shift_operator(node, source) {
                if let Some(left) = node.child_by_field_name("left") {
                    if let Some(lr) = try_evaluate_range(&left, source, macros, &var_ranges) {
                        if lr.min < 0 {
                            return false;
                        }
                    }
                }
            }
        }
        return range.fits_in_signed(bits);
    }
    false
}

/// Returns true if the expression provably fits in an unsigned integer of the given bit width.
pub fn expression_fits_in_unsigned(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    bits: u32,
) -> bool {
    let loop_ranges = extract_loop_var_ranges(node, source, macros);
    let mut var_ranges = loop_ranges.clone();
    resolve_identifiers_in_expr(node, source, macros, &loop_ranges, &mut var_ranges);

    if let Some(range) = try_evaluate_range(node, source, macros, &var_ranges) {
        return range.fits_in_unsigned(bits);
    }
    false
}

/// VRA-backed version of `expression_fits_in_signed`.
/// Tries CFG-based value-range analysis first, falls back to syntactic analysis.
pub fn expression_fits_in_signed_vra(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    bits: u32,
    vra_var_ranges: Option<&VarRangeMap>,
) -> bool {
    // Try VRA-provided ranges first
    if let Some(var_ranges) = vra_var_ranges {
        if let Some(range) = try_evaluate_range(node, source, macros, var_ranges) {
            // For left shift: shifting negative values is UB even if result fits
            if node.kind() == "binary_expression" && is_shift_operator(node, source) {
                if range.min < 0 {
                    return false;
                }
                if let Some(left) = node.child_by_field_name("left") {
                    if let Some(lr) = try_evaluate_range(&left, source, macros, var_ranges) {
                        if lr.min < 0 {
                            return false;
                        }
                    }
                }
            }
            return range.fits_in_signed(bits);
        }
    }
    // Fallback to syntactic analysis
    expression_fits_in_signed(node, source, macros, bits)
}

/// Returns true only when the expression *definitely* overflows the signed
/// bound — i.e. its entire computed value range lies outside the representable
/// band (every value overflows), such as `INT_MAX + 1` → `[INT_MAX+1,
/// INT_MAX+1]` or `SHRT_MAX + 1` (width-sensitive).
///
/// This is deliberately stronger than `!expression_fits_in_signed_vra`: a range
/// that merely *straddles* the bound (e.g. a parameter VRA-defaulted to the full
/// type range `[INT_MIN, INT_MAX]`, whose `+1` is `[INT_MIN+1, INT_MAX+1]`) is a
/// *possible*, not definite, overflow and returns false. The INT32-C provenance
/// gate uses this so constant-MAX overflows still fire while operands with
/// unknown-but-practically-bounded ranges stay suppressed. Returns false
/// whenever the range cannot be computed.
pub fn expression_overflows_signed_vra(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    bits: u32,
    vra_var_ranges: Option<&VarRangeMap>,
) -> bool {
    if bits == 0 || bits > 63 {
        return false;
    }
    if let Some(var_ranges) = vra_var_ranges {
        // Left-shifting a definitely-negative value is undefined whatever the
        // result's magnitude, so no overflow-band check can prove it. Requiring
        // the whole left range to be negative keeps this as *definite* as the
        // band check below.
        if node.kind() == "binary_expression" && is_left_shift(node, source) {
            if let Some(left) = node.child_by_field_name("left") {
                if let Some(lr) = try_evaluate_range(&left, source, macros, var_ranges) {
                    if lr.max < 0 {
                        return true;
                    }
                }
            }
        }
        if let Some(range) = try_evaluate_range(node, source, macros, var_ranges) {
            let signed_max = (1i64 << (bits - 1)) - 1;
            let signed_min = -(1i64 << (bits - 1));
            // Definite overflow: the whole range is above max or below min.
            return range.min > signed_max || range.max < signed_min;
        }
    }
    false
}

/// Unsigned analogue of [`expression_overflows_signed_vra`]: returns true only
/// when the expression *definitely* wraps an unsigned `bits`-wide type — its
/// entire computed range lies above the unsigned max (e.g. `UINT_MAX + 1`) or
/// entirely below zero (a definite underflow/wrap such as `0u - 1`). A range
/// that merely straddles a bound (an unknown-but-bounded operand) is a
/// *possible*, not definite, wrap and returns false, so bounded unsigned
/// counters stay suppressed. Returns false whenever the range cannot be
/// computed.
pub fn expression_overflows_unsigned_vra(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    bits: u32,
    vra_var_ranges: Option<&VarRangeMap>,
) -> bool {
    if bits == 0 {
        return false;
    }
    if let Some(var_ranges) = vra_var_ranges {
        if let Some(range) = try_evaluate_range(node, source, macros, var_ranges) {
            // A range entirely below zero wraps whatever the width is: `0u - 1`
            // is as much a wrap in `size_t` as in `unsigned`. Answering this
            // half only for widths under 64 made a caller that correctly
            // reported a 64-bit operation's width lose the definite-underflow
            // channel entirely, which reads as "proven safe".
            if range.max < 0 {
                return true;
            }
            // The other half is only expressible below 63 bits: an `i64` range
            // can never sit entirely above `2^63 - 1`, and forming the bound
            // there would overflow the shift that computes it.
            if bits >= 63 {
                return false;
            }
            let unsigned_max = (1i64 << bits) - 1;
            return range.min > unsigned_max;
        }
    }
    false
}

/// VRA-backed version of `expression_fits_in_unsigned`.
/// Tries CFG-based value-range analysis first, falls back to syntactic analysis.
pub fn expression_fits_in_unsigned_vra(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    bits: u32,
    vra_var_ranges: Option<&VarRangeMap>,
) -> bool {
    // Try VRA-provided ranges first.
    // VRA is used only to PROVE SAFETY (suppress): if VRA says the result fits,
    // return true immediately. If VRA says overflow is possible, fall through to
    // syntactic analysis — VRA's loop widening can be over-conservative (e.g.
    // widening data to UINT_MAX after `data=2` in a bounded loop), and the
    // syntactic path has separate constant-propagation that handles those cases.
    if let Some(var_ranges) = vra_var_ranges {
        if let Some(range) = try_evaluate_range(node, source, macros, var_ranges) {
            if range.fits_in_unsigned(bits) {
                return true;
            }
        }
    }
    // Fallback to syntactic analysis
    expression_fits_in_unsigned(node, source, macros, bits)
}

/// Resolve identifiers in an expression by scanning local assignments.
pub fn resolve_identifiers_in_expr(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    loop_ranges: &VarRangeMap,
    var_ranges: &mut VarRangeMap,
) {
    if node.kind() == "identifier" {
        let name = node.utf8_text(source.as_bytes()).unwrap_or("");
        if !name.is_empty() && !macros.contains_key(name) && !var_ranges.contains_key(name) {
            if let Some(range) = resolve_local_var_range(name, node, source, macros, loop_ranges) {
                var_ranges.insert(name.to_string(), range);
            }
        }
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            resolve_identifiers_in_expr(&child, source, macros, loop_ranges, var_ranges);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The operator text of an `assignment_expression` (`=`, `+=`, `<<=`, ...).
/// Exposed as the `operator` field by the grammar; the scan is the same
/// fallback `value_range::get_assignment_operator` keeps for older trees.
fn assignment_operator_text(node: &Node, source: &str) -> String {
    if let Some(op) = node.child_by_field_name("operator") {
        if let Ok(text) = op.utf8_text(source.as_bytes()) {
            return text.to_string();
        }
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            let kind = child.kind();
            if matches!(
                kind,
                "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "<<=" | ">>=" | "&=" | "|=" | "^="
            ) {
                return kind.to_string();
            }
        }
    }
    "=".to_string()
}

/// True when `node` is a `<<` expression specifically (not `>>`).
fn is_left_shift(node: &Node, source: &str) -> bool {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "<<" {
                return true;
            }
            if let Ok(text) = child.utf8_text(source.as_bytes()) {
                if text == "<<" {
                    return true;
                }
            }
        }
    }
    false
}

fn is_shift_operator(node: &Node, source: &str) -> bool {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "<<" || child.kind() == ">>" {
                return true;
            }
            // Also check text content for operator nodes
            if let Ok(text) = child.utf8_text(source.as_bytes()) {
                if text == "<<" || text == ">>" {
                    return true;
                }
            }
        }
    }
    false
}

fn get_operator_text(node: &Node, source: &str) -> String {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            let kind = child.kind();
            if matches!(
                kind,
                "<" | "<="
                    | ">"
                    | ">="
                    | "=="
                    | "!="
                    | "+"
                    | "-"
                    | "*"
                    | "/"
                    | "<<"
                    | ">>"
                    | "&&"
                    | "||"
            ) {
                return child.utf8_text(source.as_bytes()).unwrap_or("").to_string();
            }
        }
    }
    String::new()
}

/// Parse a C char literal like `' '`, `'a'`, `'\n'`, `'\0'`, `'\x41'` into its integer value.
fn parse_char_literal(text: &str) -> Option<u8> {
    // Expect surrounding single quotes, possibly with L/u/U prefix
    let inner = text.strip_prefix('\'').or_else(|| {
        text.strip_prefix("L'")
            .or_else(|| text.strip_prefix("u'"))
            .or_else(|| text.strip_prefix("U'"))
    })?;
    let inner = inner.strip_suffix('\'')?;

    if let Some(escaped) = inner.strip_prefix('\\') {
        match escaped.as_bytes().first()? {
            b'n' => Some(b'\n'),
            b't' => Some(b'\t'),
            b'r' => Some(b'\r'),
            b'0' if escaped.len() == 1 => Some(0),
            b'\\' => Some(b'\\'),
            b'\'' => Some(b'\''),
            b'"' => Some(b'"'),
            b'a' => Some(7),
            b'b' => Some(8),
            b'f' => Some(12),
            b'v' => Some(11),
            b'x' => u8::from_str_radix(&escaped[1..], 16).ok(),
            d if d.is_ascii_digit() => u8::from_str_radix(escaped, 8).ok(),
            _ => None,
        }
    } else {
        let ch = inner.chars().next()?;
        if ch.is_ascii() {
            Some(ch as u8)
        } else {
            None
        }
    }
}

fn parse_integer_literal(text: &str) -> Option<i64> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    // Handle negative literals
    if let Some(rest) = text.strip_prefix('-') {
        let val = parse_unsigned_literal(rest.trim())?;
        return val.checked_neg();
    }
    parse_unsigned_literal(text)
}

fn parse_unsigned_literal(text: &str) -> Option<i64> {
    let text = strip_integer_suffix(text);
    if text.starts_with("0x") || text.starts_with("0X") {
        i64::from_str_radix(&text[2..], 16).ok()
    } else if text.starts_with("0b") || text.starts_with("0B") {
        i64::from_str_radix(&text[2..], 2).ok()
    } else if text.starts_with('0') && text.len() > 1 && text.chars().all(|c| c.is_ascii_digit()) {
        i64::from_str_radix(&text[1..], 8).ok()
    } else {
        text.parse::<i64>().ok()
    }
}

fn strip_integer_suffix(text: &str) -> &str {
    // Strip trailing: ULL, ull, UL, ul, LL, ll, U, u, L, l
    let suffixes = [
        "ULL", "ull", "Ull", "uLL", "UL", "ul", "Ul", "uL", "LL", "ll", "U", "u", "L", "l",
    ];
    for suffix in &suffixes {
        if let Some(stripped) = text.strip_suffix(suffix) {
            return stripped;
        }
    }
    text
}

fn is_c_identifier(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
        && text.chars().all(|c| c.is_alphanumeric() || c == '_')
}

fn parens_balanced(text: &str) -> bool {
    let mut depth = 0i32;
    for ch in text.chars() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written_names(code: &str) -> std::collections::HashSet<String> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        file_scope_written_names(&tree.root_node(), code)
    }

    #[test]
    fn written_names_holds_every_file_scope_write_and_no_local_one() {
        let w = written_names(
            "int a, b, c, d, e, f;\n\
             void g(int f) { int e; a = 1; ++b; int *p = &c; e = 2; f = 3; }\n\
             void h(void) { extern int d; d = 4; }\n",
        );
        for name in ["a", "b", "c", "d"] {
            assert!(w.contains(name), "{name} is written at file scope");
        }
        // A local and a parameter of the same spelling are other objects.
        assert!(!w.contains("e"));
        assert!(!w.contains("f"));
    }

    #[test]
    fn written_names_counts_macro_bodies_and_function_macro_arguments() {
        let w = written_names(
            "int a, b, c;\n\
             #define BUMP() (a++)\n\
             #define SET(v) ((v) = 1)\n\
             void g(void) { SET(b); (void)c; }\n",
        );
        assert!(w.contains("a"), "named in a #define body");
        assert!(w.contains("b"), "an argument of a function-like macro");
        assert!(!w.contains("c"), "only read");
    }

    fn never_written(code: &str, name: &str) -> bool {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        file_static_never_written(&tree.root_node(), code, name)
    }

    #[test]
    fn a_static_written_where_the_parse_cannot_see_is_written() {
        assert!(never_written(
            "static int d = 0;\nint f(void) { int d = 1; d = 2; return d; }\n",
            "d"
        ));
        assert!(!never_written(
            "static int v = 0;\n#define SET() (v = 1)\nvoid on(void) { SET(); }\n",
            "v"
        ));
        assert!(!never_written(
            "static int d = 0;\nvoid on(void) { extern int d; d = 1; }\n",
            "d"
        ));
        assert!(!never_written(
            "static int d = 0;\n#define INC(x) ((x)++)\nvoid on(void) { INC(d); }\n",
            "d"
        ));
    }

    #[test]
    fn shr_range_is_monotone_and_refuses_unsound_operands() {
        let ten_to_twenty = ValueRange::new(10, 20);
        assert_eq!(
            ten_to_twenty.shr(&ValueRange::exact(1)),
            Some(ValueRange::new(5, 10))
        );
        // Rising with the value, falling with the amount.
        assert_eq!(
            ValueRange::new(0, 7680).shr(&ValueRange::new(9, 9)),
            Some(ValueRange::new(0, 15))
        );
        assert_eq!(
            ValueRange::new(64, 256).shr(&ValueRange::new(1, 3)),
            Some(ValueRange::new(8, 128))
        );
        // A negative value makes `>>` implementation-defined, a negative or
        // over-wide amount makes it undefined: no bound in either case.
        assert_eq!(ValueRange::new(-1, 8).shr(&ValueRange::exact(1)), None);
        assert_eq!(ten_to_twenty.shr(&ValueRange::new(-1, 2)), None);
        assert_eq!(ten_to_twenty.shr(&ValueRange::new(0, 64)), None);
    }

    #[test]
    fn a_macro_invocation_is_bounded_by_what_it_expands_to() {
        let source = "\
#define MASK(n) ((1ul << (n)) - 1ul)
#define LINEBITS(s) (((s) & MASK(3)) + 4)
int f(unsigned long s) { return LINEBITS(s); }
";
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        let fmacros = macro_expand::collect_function_macros(&root, source);
        let macros = collect_macro_constants(&root, source, crate::settings::DataModel::Lp64);
        let var_ranges = VarRangeMap::new();

        let call = lang_parsing_substrate::query::find_descendants_of_kind(root, "call_expression")
            .into_iter()
            .find(|n| ast_utils::get_node_text(n, source).starts_with("LINEBITS"))
            .expect("LINEBITS invocation");

        // Opaque without the table, and `(s & 7) + 4` with it.
        assert_eq!(
            try_evaluate_range(&call, source, &macros, &var_ranges),
            None
        );
        assert_eq!(
            try_evaluate_range_expanding(&call, source, &macros, &var_ranges, &fmacros),
            Some(ValueRange::new(4, 11))
        );
    }

    #[test]
    fn test_parse_integer_literal() {
        assert_eq!(parse_integer_literal("42"), Some(42));
        assert_eq!(parse_integer_literal("0xFF"), Some(255));
        assert_eq!(parse_integer_literal("0x1F"), Some(31));
        assert_eq!(parse_integer_literal("010"), Some(8));
        assert_eq!(parse_integer_literal("0"), Some(0));
        assert_eq!(parse_integer_literal("-1"), Some(-1));
        assert_eq!(parse_integer_literal("50UL"), Some(50));
        assert_eq!(parse_integer_literal("1000LL"), Some(1000));
    }

    #[test]
    fn test_try_evaluate_text_simple() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("42", &macros), Some(42));
        assert_eq!(try_evaluate_text("(42)", &macros), Some(42));
        assert_eq!(try_evaluate_text("50 * 1000", &macros), Some(50000));
        assert_eq!(try_evaluate_text("250 * 1000", &macros), Some(250000));
    }

    #[test]
    fn test_try_evaluate_text_with_macros() {
        let mut macros = MacroConstantMap::new();
        macros.insert("DELAY_MS".to_string(), 50);
        assert_eq!(try_evaluate_text("DELAY_MS", &macros), Some(50));
        assert_eq!(try_evaluate_text("DELAY_MS * 1000", &macros), Some(50000));
        assert_eq!(try_evaluate_text("(DELAY_MS * 1000)", &macros), Some(50000));
    }

    #[test]
    fn test_try_evaluate_text_shift() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("1 << 4", &macros), Some(16));
        assert_eq!(try_evaluate_text("500 * (1 << 1)", &macros), Some(1000));
    }

    #[test]
    fn test_collect_macro_constants_chained() {
        let mut macros = MacroConstantMap::new();
        macros.insert("A".to_string(), 10);
        // Simulates A * 5 where A=10
        assert_eq!(try_evaluate_text("A * 5", &macros), Some(50));
    }

    #[test]
    fn test_value_range_fits() {
        let r = ValueRange::new(0, 50000);
        assert!(r.fits_in_signed(32)); // [-2^31, 2^31-1] easily fits 50000
        assert!(r.fits_in_unsigned(16)); // [0, 65535] fits 50000
        assert!(!r.fits_in_unsigned(15)); // [0, 32767] doesn't fit 50000

        let r2 = ValueRange::new(-100, 100);
        assert!(r2.fits_in_signed(8)); // [-128, 127]
        assert!(!r2.fits_in_unsigned(8)); // negative min
    }

    #[test]
    fn test_value_range_mul() {
        let a = ValueRange::new(0, 50);
        let b = ValueRange::exact(1000);
        let result = a.mul(&b).unwrap();
        assert_eq!(result.min, 0);
        assert_eq!(result.max, 50000);
        assert!(result.fits_in_signed(32));
    }

    #[test]
    fn test_value_range_shl() {
        let a = ValueRange::exact(500);
        let b = ValueRange::new(0, 1);
        let result = a.shl(&b).unwrap();
        assert_eq!(result.min, 500);
        assert_eq!(result.max, 1000);
        assert!(result.fits_in_signed(32));
    }

    // --- New tests for uncovered branches ---

    #[test]
    fn test_try_evaluate_text_addition_subtraction() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("10 + 20", &macros), Some(30));
        assert_eq!(try_evaluate_text("100 - 37", &macros), Some(63));
        assert_eq!(try_evaluate_text("5 + 3 + 2", &macros), Some(10));
    }

    #[test]
    fn test_try_evaluate_text_division() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("100 / 5", &macros), Some(20));
        assert_eq!(try_evaluate_text("100 / 0", &macros), None); // div by zero
        assert_eq!(try_evaluate_text("7 / 2", &macros), Some(3)); // truncation
    }

    #[test]
    fn test_try_evaluate_text_right_shift() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("256 >> 4", &macros), Some(16));
        assert_eq!(try_evaluate_text("1 >> 0", &macros), Some(1));
    }

    #[test]
    fn test_try_evaluate_text_precedence() {
        let macros = MacroConstantMap::new();
        // * has higher precedence than +
        assert_eq!(try_evaluate_text("2 + 3 * 4", &macros), Some(14));
        // parens override
        assert_eq!(try_evaluate_text("(2 + 3) * 4", &macros), Some(20));
    }

    #[test]
    fn test_try_evaluate_text_arrow_not_minus() {
        let macros = MacroConstantMap::new();
        // "a->b" should not parse as subtraction; returns None (not a constant)
        assert_eq!(try_evaluate_text("a->b", &macros), None);
    }

    #[test]
    fn test_try_evaluate_text_builtin_macros() {
        let macros = builtin_constants(DataModel::Lp64).clone();
        assert_eq!(try_evaluate_text("INT_MAX", &macros), Some(2147483647));
        assert_eq!(try_evaluate_text("CHAR_BIT", &macros), Some(8));
        assert_eq!(try_evaluate_text("INT_MAX + 1", &macros), Some(2147483648));
    }

    #[test]
    fn test_try_evaluate_text_nested_parens() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("(10)", &macros), Some(10));
        assert_eq!(try_evaluate_text("(2 + 3) * (4 + 1)", &macros), Some(25));
        assert_eq!(try_evaluate_text("((10))", &macros), Some(10));
        assert_eq!(try_evaluate_text("((2 + 3) * (4 + 1))", &macros), Some(25));
    }

    #[test]
    fn test_parse_integer_literal_binary() {
        assert_eq!(parse_integer_literal("0b1010"), Some(10));
        assert_eq!(parse_integer_literal("0B11"), Some(3));
    }

    #[test]
    fn test_parse_integer_literal_edge_cases() {
        assert_eq!(parse_integer_literal(""), None);
        assert_eq!(parse_integer_literal("0xFFFFFFFF"), Some(4294967295));
        assert_eq!(parse_integer_literal("100ULL"), Some(100));
    }

    #[test]
    fn test_is_c_identifier() {
        assert!(is_c_identifier("foo"));
        assert!(is_c_identifier("_bar"));
        assert!(is_c_identifier("baz123"));
        assert!(!is_c_identifier(""));
        assert!(!is_c_identifier("123abc"));
        assert!(!is_c_identifier("a-b"));
    }

    #[test]
    fn test_parens_balanced() {
        assert!(parens_balanced("()"));
        assert!(parens_balanced("(a + (b * c))"));
        assert!(parens_balanced("no_parens"));
        assert!(!parens_balanced("("));
        assert!(!parens_balanced(")"));
        assert!(!parens_balanced(")("));
        assert!(!parens_balanced("((())"));
    }

    #[test]
    fn test_value_range_add() {
        let a = ValueRange::new(10, 20);
        let b = ValueRange::new(5, 15);
        let result = a.add(&b).unwrap();
        assert_eq!(result.min, 15);
        assert_eq!(result.max, 35);
    }

    #[test]
    fn test_value_range_sub() {
        let a = ValueRange::new(10, 20);
        let b = ValueRange::new(5, 15);
        let result = a.sub(&b).unwrap();
        assert_eq!(result.min, -5); // 10 - 15
        assert_eq!(result.max, 15); // 20 - 5
    }

    #[test]
    fn test_value_range_fits_edge_cases() {
        // 0-bit width
        assert!(!ValueRange::exact(0).fits_in_signed(0));
        assert!(!ValueRange::exact(0).fits_in_unsigned(0));

        // 64-bit always fits for signed
        assert!(ValueRange::new(i64::MIN, i64::MAX).fits_in_signed(64));

        // 64-bit unsigned
        assert!(ValueRange::new(0, i64::MAX).fits_in_unsigned(64));
        assert!(!ValueRange::new(-1, 0).fits_in_unsigned(64));
    }

    #[test]
    fn test_value_range_shl_invalid_shift() {
        let a = ValueRange::exact(1);
        let b = ValueRange::new(0, 100); // max > 63
        assert!(a.shl(&b).is_none());
    }

    #[test]
    fn test_collect_macro_constants_from_ast() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "#define MY_CONST 42\n#define DOUBLE_CONST (MY_CONST * 2)\nint x;\n";
        let tree = parser.parse(code, None).unwrap();
        let macros =
            collect_macro_constants(&tree.root_node(), code, crate::settings::DataModel::Lp64);
        assert_eq!(macros.get("MY_CONST"), Some(&42));
        assert_eq!(macros.get("DOUBLE_CONST"), Some(&84));
    }

    #[test]
    fn an_alias_defined_two_ways_is_unsettled_and_keeps_both_targets() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "#ifdef USE_WIDE
                    #define CHDIR _wchdir
                    #else
                    #define CHDIR chdir
                    #endif
                    #define RUN system
";
        let tree = parser.parse(code, None).unwrap();
        let root = tree.root_node();
        let aliases = collect_macro_aliases(&root, code);
        assert_eq!(aliases.get("CHDIR"), None);
        assert_eq!(aliases.get("RUN").map(String::as_str), Some("system"));
        let alternatives = collect_macro_alias_alternatives(&root, code);
        assert_eq!(alternatives["CHDIR"], vec!["_wchdir", "chdir"]);
        assert_eq!(
            resolve_macro_alias_where(&alternatives, "CHDIR", |t| t == "chdir").as_deref(),
            Some("chdir")
        );
        assert_eq!(
            resolve_macro_alias_where(&alternatives, "CHDIR", |t| t == "rmdir"),
            None
        );
        // The file's own definitions override a name the project settled.
        let project: HashMap<String, String> = [("CHDIR".to_string(), "chdir".to_string())].into();
        assert_eq!(
            merged_macro_aliases(&project, &root, code).get("CHDIR"),
            None
        );
        // An accusing consumer maps the unsettled name to the target it
        // looks for.
        let mut accusing = aliases.clone();
        with_accusing_alias_targets(&mut accusing, &alternatives, |t| t == "chdir");
        assert_eq!(accusing.get("CHDIR").map(String::as_str), Some("chdir"));
    }

    #[test]
    fn an_alias_every_target_agrees_on_settles_for_a_suppressing_consumer() {
        let alternatives: HashMap<String, Vec<String>> = [
            (
                "my_free".to_string(),
                vec!["HOOK_FREE".to_string(), "free".to_string()],
            ),
            (
                "odd_free".to_string(),
                vec!["HOOK_PUT".to_string(), "free".to_string()],
            ),
            (
                "maybe_free".to_string(),
                vec!["unknown_hook".to_string(), "free".to_string()],
            ),
            (
                "via".to_string(),
                vec!["my_free".to_string(), "FREE_ALIAS".to_string()],
            ),
        ]
        .into();
        let role = |t: &str| match t {
            "free" | "HOOK_FREE" => Some(0),
            "HOOK_PUT" => Some(1),
            _ => None,
        };
        let mut aliases: HashMap<String, String> =
            [("FREE_ALIAS".to_string(), "free".to_string())].into();
        with_agreeing_alias_targets(&mut aliases, &alternatives, role);
        assert_eq!(
            aliases.get("my_free").map(String::as_str),
            Some("HOOK_FREE")
        );
        // The arms disagree on the argument, or one arm is unknown.
        assert_eq!(aliases.get("odd_free"), None);
        assert_eq!(aliases.get("maybe_free"), None);
        // `my_free` is itself unsettled when `via` is read, and a target is
        // resolved through the settled map only.
        assert_eq!(aliases.get("via"), None);
    }

    #[test]
    fn platform_dead_defines_are_not_collected() {
        // hostap common.h's `_MSC_VER` arm: `#define close closesocket` is an
        // alias no POSIX build has. And a `#ifndef _WIN32` / `#else` split
        // used to hand last-wins the Windows value.
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "#ifdef _MSC_VER
                    #define close closesocket
                    #endif
                    #ifndef _WIN32
                    #define PATH_MAX_LEN 4096
                    #else
                    #define PATH_MAX_LEN 260
                    #endif
                    #ifdef CONFIG_FOO
                    #define TUNABLE 1
                    #else
                    #define TUNABLE 2
                    #endif
";
        let tree = parser.parse(code, None).unwrap();
        let aliases = collect_macro_aliases(&tree.root_node(), code);
        assert!(!aliases.contains_key("close"), "{:?}", aliases);
        let macros =
            collect_macro_constants(&tree.root_node(), code, crate::settings::DataModel::Lp64);
        assert_eq!(macros.get("PATH_MAX_LEN"), Some(&4096));
        // A build-config guard stays unsettled: the constant resolver's
        // first-wins tie-break applies exactly as before.
        assert_eq!(macros.get("TUNABLE"), Some(&1));
    }

    #[test]
    fn test_collect_macro_aliases_from_ast() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "#define SYSTEM system\n#define BUFSIZE 1024\nint x;\n";
        let tree = parser.parse(code, None).unwrap();
        let aliases = collect_macro_aliases(&tree.root_node(), code);
        assert_eq!(aliases.get("SYSTEM"), Some(&"system".to_string()));
        // BUFSIZE is numeric, should NOT be in aliases
        assert!(!aliases.contains_key("BUFSIZE"));
    }

    #[test]
    fn test_merged_macro_constants_per_file_wins() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "#define MY_CONST 42\n#define FILE_ONLY 7\nint x;\n";
        let tree = parser.parse(code, None).unwrap();
        let mut project = MacroConstantMap::new();
        project.insert("MY_CONST".to_string(), 0); // overridden by the file's definition
        project.insert("PROJECT_ONLY".to_string(), 99);
        let merged = merged_macro_constants(
            &project,
            &tree.root_node(),
            code,
            crate::settings::DataModel::Lp64,
        );
        assert_eq!(merged.get("MY_CONST"), Some(&42));
        assert_eq!(merged.get("FILE_ONLY"), Some(&7));
        assert_eq!(merged.get("PROJECT_ONLY"), Some(&99));
    }

    #[test]
    fn test_merged_macro_aliases_per_file_wins() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "#define SYSTEM system\n";
        let tree = parser.parse(code, None).unwrap();
        let mut project = HashMap::new();
        project.insert("SYSTEM".to_string(), "popen".to_string()); // overridden by the file's definition
        project.insert("PROJECT_ONLY".to_string(), "exec".to_string());
        let merged = merged_macro_aliases(&project, &tree.root_node(), code);
        assert_eq!(merged.get("SYSTEM"), Some(&"system".to_string()));
        assert_eq!(merged.get("PROJECT_ONLY"), Some(&"exec".to_string()));
    }

    /// `#define mbedtls_calloc calloc` is the whole mbedtls allocator story:
    /// one hop, a chain, a non-alias, and a cycle must all
    /// resolve without looping.
    #[test]
    fn test_resolve_macro_alias_follows_chains_and_stops_on_cycles() {
        let mut aliases = HashMap::new();
        aliases.insert("mbedtls_calloc".to_string(), "calloc".to_string());
        aliases.insert("port_free".to_string(), "mbedtls_free".to_string());
        aliases.insert("mbedtls_free".to_string(), "free".to_string());
        aliases.insert("ping".to_string(), "pong".to_string());
        aliases.insert("pong".to_string(), "ping".to_string());
        assert_eq!(resolve_macro_alias(&aliases, "mbedtls_calloc"), "calloc");
        assert_eq!(resolve_macro_alias(&aliases, "port_free"), "free");
        assert_eq!(resolve_macro_alias(&aliases, "malloc"), "malloc");
        let looped = resolve_macro_alias(&aliases, "ping");
        assert!(looped == "ping" || looped == "pong");
    }

    #[test]
    fn test_try_evaluate_expr_ast() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "int x = 10 + 20;\n";
        let tree = parser.parse(code, None).unwrap();
        let macros = MacroConstantMap::new();

        // Navigate to the binary expression: translation_unit > declaration > init_declarator > value
        let root = tree.root_node();
        let decl = root.child(0).unwrap();
        let init = decl.child_by_field_name("declarator").unwrap();
        if let Some(value) = init.child_by_field_name("value") {
            let result = try_evaluate_expr(&value, code, &macros);
            assert_eq!(result, Some(30));
        }
    }

    // --- Tests for sizeof resolution ---

    #[test]
    fn test_resolve_sizeof_type_basic() {
        let lp64 = builtin_constants(DataModel::Lp64);
        let size = |t: &str| resolve_sizeof_type(t, lp64);
        assert_eq!(size("char"), Some(1));
        assert_eq!(size("unsigned char"), Some(1));
        assert_eq!(size("int8_t"), Some(1));
        assert_eq!(size("bool"), Some(1));
        assert_eq!(size("_Bool"), Some(1));
        assert_eq!(size("short"), Some(2));
        assert_eq!(size("uint16_t"), Some(2));
        assert_eq!(size("int"), Some(4));
        assert_eq!(size("unsigned int"), Some(4));
        assert_eq!(size("float"), Some(4));
        assert_eq!(size("wchar_t"), Some(4));
        assert_eq!(size("long"), Some(8));
        assert_eq!(size("double"), Some(8));
        assert_eq!(size("size_t"), Some(8));
        assert_eq!(size("long double"), Some(16));
        let llp64 = builtin_constants(DataModel::Llp64);
        assert_eq!(resolve_sizeof_type("long", llp64), Some(4));
        assert_eq!(resolve_sizeof_type("wchar_t", llp64), Some(2));
    }

    #[test]
    fn test_resolve_sizeof_type_pointers() {
        let lp64 = builtin_constants(DataModel::Lp64);
        assert_eq!(resolve_sizeof_type("int *", lp64), Some(8));
        assert_eq!(resolve_sizeof_type("char *", lp64), Some(8));
        assert_eq!(resolve_sizeof_type("void *", lp64), Some(8));
        let ilp32 = builtin_constants(DataModel::Ilp32);
        assert_eq!(resolve_sizeof_type("void *", ilp32), Some(4));
    }

    #[test]
    fn iso_fixes_only_the_char_sizes_and_the_exact_width_limits() {
        let iso = builtin_constants(DataModel::Iso);
        assert_eq!(resolve_sizeof_type("unsigned char", iso), Some(1));
        assert_eq!(resolve_sizeof_type("int", iso), None);
        assert_eq!(resolve_sizeof_type("void *", iso), None);
        assert_eq!(try_evaluate_text("INT_MAX", iso), None);
        assert_eq!(try_evaluate_text("INT32_MAX", iso), Some(2147483647));
        // sizeof(long) is not "some object of at least one byte".
        assert_eq!(try_evaluate_text("sizeof(long)", iso), None);
        assert_eq!(try_evaluate_text("sizeof(widget)", iso), Some(1));
    }

    #[test]
    fn a_files_own_definition_of_a_limit_wins_over_the_builtin() {
        let code = "#define INT_MAX 32767\n#define HALF (INT_MAX / 2)\n";
        let (tree, source) = crate::parser::CParser::new()
            .unwrap()
            .parse_source(code)
            .unwrap();
        let macros = collect_macro_constants(&tree.root_node(), &source, DataModel::Lp64);
        assert_eq!(macros.get("INT_MAX"), Some(&32767));
        assert_eq!(macros.get("HALF"), Some(&16383));
        let iso = collect_macro_constants(&tree.root_node(), &source, DataModel::Iso);
        assert_eq!(iso.get("HALF"), Some(&16383));
    }

    #[test]
    fn test_sizeof_type_bounds_exact_width() {
        assert_eq!(sizeof_type_bounds("uint64_t"), Some(ValueRange::new(1, 8)));
        assert_eq!(sizeof_type_bounds("int16_t"), Some(ValueRange::new(1, 2)));
        assert_eq!(sizeof_type_bounds("long"), None);
        assert_eq!(sizeof_type_bounds("struct foo"), None);
    }

    #[test]
    fn test_resolve_sizeof_type_unknown() {
        let lp64 = builtin_constants(DataModel::Lp64);
        assert_eq!(resolve_sizeof_type("struct foo", lp64), None);
        assert_eq!(resolve_sizeof_type("my_custom_type", lp64), None);
    }

    #[test]
    fn test_resolve_sizeof_node_ast() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "int x = sizeof(int);\n";
        let tree = parser.parse(code, None).unwrap();
        let root = tree.root_node();
        let decl = root.child(0).unwrap();
        // Navigate to init_declarator → value (sizeof_expression)
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        let macros = builtin_constants(DataModel::Lp64);
                        let result = try_evaluate_expr(&value, code, macros);
                        assert_eq!(result, Some(4), "sizeof(int) should be 4 on LP64");
                        let iso = builtin_constants(DataModel::Iso);
                        assert_eq!(try_evaluate_expr(&value, code, iso), None);
                    }
                }
            }
        }
    }

    // --- Tests for AST-based try_evaluate_expr branches ---

    #[test]
    fn test_try_evaluate_expr_unary() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "int x = -42;\n";
        let tree = parser.parse(code, None).unwrap();
        let macros = MacroConstantMap::new();
        let root = tree.root_node();
        let decl = root.child(0).unwrap();
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        assert_eq!(try_evaluate_expr(&value, code, &macros), Some(-42));
                    }
                }
            }
        }
    }

    #[test]
    fn test_try_evaluate_expr_cast() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "int x = (int)42;\n";
        let tree = parser.parse(code, None).unwrap();
        let macros = MacroConstantMap::new();
        let root = tree.root_node();
        let decl = root.child(0).unwrap();
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        assert_eq!(try_evaluate_expr(&value, code, &macros), Some(42));
                    }
                }
            }
        }
    }

    #[test]
    fn test_try_evaluate_expr_modulo() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "int x = 17 % 5;\n";
        let tree = parser.parse(code, None).unwrap();
        let macros = MacroConstantMap::new();
        let root = tree.root_node();
        let decl = root.child(0).unwrap();
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        assert_eq!(try_evaluate_expr(&value, code, &macros), Some(2));
                    }
                }
            }
        }
    }

    // --- Tests for try_evaluate_range ---

    #[test]
    fn test_try_evaluate_range_binary_ops() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "int x = a + 10;\n";
        let tree = parser.parse(code, None).unwrap();
        let macros = MacroConstantMap::new();
        let mut var_ranges = VarRangeMap::new();
        var_ranges.insert("a".to_string(), ValueRange::new(0, 50));

        let root = tree.root_node();
        let decl = root.child(0).unwrap();
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        let range = try_evaluate_range(&value, code, &macros, &var_ranges);
                        assert!(range.is_some());
                        let r = range.unwrap();
                        assert_eq!(r.min, 10);
                        assert_eq!(r.max, 60);
                    }
                }
            }
        }
    }

    #[test]
    fn test_try_evaluate_range_unary_neg() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "int x = -a;\n";
        let tree = parser.parse(code, None).unwrap();
        let macros = MacroConstantMap::new();
        let mut var_ranges = VarRangeMap::new();
        var_ranges.insert("a".to_string(), ValueRange::new(5, 10));

        let root = tree.root_node();
        let decl = root.child(0).unwrap();
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        let range = try_evaluate_range(&value, code, &macros, &var_ranges);
                        assert!(range.is_some());
                        let r = range.unwrap();
                        assert_eq!(r.min, -10);
                        assert_eq!(r.max, -5);
                    }
                }
            }
        }
    }

    // --- Tests for expression_fits_in_signed/unsigned ---

    #[test]
    fn test_expression_fits_in_signed_simple() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "int x = 100 + 200;\n";
        let tree = parser.parse(code, None).unwrap();
        let macros = MacroConstantMap::new();

        let root = tree.root_node();
        let decl = root.child(0).unwrap();
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        assert!(expression_fits_in_signed(&value, code, &macros, 16));
                        assert!(expression_fits_in_signed(&value, code, &macros, 32));
                    }
                }
            }
        }
    }

    #[test]
    fn test_expression_fits_in_unsigned_simple() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = "int x = 100;\n";
        let tree = parser.parse(code, None).unwrap();
        let macros = MacroConstantMap::new();

        let root = tree.root_node();
        let decl = root.child(0).unwrap();
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        assert!(expression_fits_in_unsigned(&value, code, &macros, 8));
                        assert!(expression_fits_in_unsigned(&value, code, &macros, 16));
                    }
                }
            }
        }
    }

    // --- Tests for extract_loop_var_ranges ---

    #[test]
    fn test_extract_loop_var_ranges_for() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let code = r#"
void foo() {
    for (int i = 0; i < 10; i++) {
        int x = i;
    }
}
"#;
        let tree = parser.parse(code, None).unwrap();
        let macros = MacroConstantMap::new();

        // Navigate to the identifier "i" in "int x = i;"
        fn find_identifier<'a>(
            node: &tree_sitter::Node<'a>,
            name: &str,
            source: &str,
        ) -> Option<tree_sitter::Node<'a>> {
            if node.kind() == "identifier" && node.utf8_text(source.as_bytes()).ok() == Some(name) {
                // Check this is an rvalue usage (inside init_declarator value)
                if let Some(parent) = node.parent() {
                    if parent.kind() != "init_declarator"
                        || parent.child_by_field_name("value").map(|v| v.id()) == Some(node.id())
                    {
                        return Some(*node);
                    }
                }
            }
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if let Some(found) = find_identifier(&child, name, source) {
                        return Some(found);
                    }
                }
            }
            None
        }

        let root = tree.root_node();
        // Find the "i" in the assignment "int x = i"
        if let Some(i_node) = find_identifier(&root, "i", code) {
            let ranges = extract_loop_var_ranges(&i_node, code, &macros);
            if let Some(range) = ranges.get("i") {
                assert!(
                    range.max <= 9,
                    "i should be bounded to < 10, got max={}",
                    range.max
                );
            }
        }
    }

    // --- Tests for strip_integer_suffix ---

    #[test]
    fn test_strip_integer_suffix_cases() {
        assert_eq!(strip_integer_suffix("42ULL"), "42");
        assert_eq!(strip_integer_suffix("42ull"), "42");
        assert_eq!(strip_integer_suffix("42UL"), "42");
        assert_eq!(strip_integer_suffix("42ul"), "42");
        assert_eq!(strip_integer_suffix("42U"), "42");
        assert_eq!(strip_integer_suffix("42u"), "42");
        assert_eq!(strip_integer_suffix("42LL"), "42");
        assert_eq!(strip_integer_suffix("42ll"), "42");
        assert_eq!(strip_integer_suffix("42L"), "42");
        assert_eq!(strip_integer_suffix("42l"), "42");
        assert_eq!(strip_integer_suffix("42"), "42");
    }

    // --- Tests for try_evaluate_text edge cases ---

    #[test]
    fn test_try_evaluate_text_unary_negation() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("-5", &macros), Some(-5));
        assert_eq!(try_evaluate_text("-0", &macros), Some(0));
    }

    #[test]
    fn test_try_evaluate_text_comment_stripping() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("42 // comment", &macros), Some(42));
    }

    #[test]
    fn test_try_evaluate_text_suffixed_literal() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("42ULL", &macros), Some(42));
        assert_eq!(try_evaluate_text("100ul", &macros), Some(100));
    }

    #[test]
    fn test_try_evaluate_text_empty_and_whitespace() {
        let macros = MacroConstantMap::new();
        assert_eq!(try_evaluate_text("", &macros), None);
        assert_eq!(try_evaluate_text("  42  ", &macros), Some(42));
    }
}
