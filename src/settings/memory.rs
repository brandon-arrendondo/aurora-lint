//! Allocator and deallocator names a project declares: the
//! `[environment.allocators]` and `[environment.deallocators]` tables and
//! the `--allocator` / `--deallocator` flags.
//!
//! A function the scan has no body for (a platform hook such as mbedtls's
//! `MBEDTLS_PLATFORM_FREE_MACRO`, which the project's user supplies at build
//! time, or a library outside the scanned tree) cannot be proven to free or
//! to allocate, and a name's spelling is not proof (ADR-0006, ADR-0011). A
//! declaration is the project's own statement of what such a function does
//! (ADR-0001, ADR-0015's environment axis): a declared deallocator frees the
//! argument it names, and a declared allocator returns fresh memory under the
//! contract of the standard allocator it names. Every consumer that asks
//! whether a call frees or allocates reads the same declarations, through
//! [`crate::utility::cert_c::call_roles`].
//!
//! One process scans under one set of declarations. [`declare`] installs it
//! before prescan, because function summaries built there already record what
//! a wrapper around a declared hook frees.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::sync::OnceLock;

/// The standard allocator whose contract a declared allocator follows: which
/// arguments carry the size, whether the memory is zeroed, and, for
/// `realloc`, that the old block passed as the first argument is released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllocatorContract {
    /// `malloc(size)`.
    Malloc,
    /// `calloc(count, size)`.
    Calloc,
    /// `realloc(old, size)`: also releases `old`.
    Realloc,
    /// `aligned_alloc(alignment, size)`.
    AlignedAlloc,
    /// `strdup(s)`.
    Strdup,
    /// `strndup(s, n)`.
    Strndup,
}

impl AllocatorContract {
    /// Every contract, in the order they are listed to a user.
    pub const ALL: [AllocatorContract; 6] = [
        Self::Malloc,
        Self::Calloc,
        Self::Realloc,
        Self::AlignedAlloc,
        Self::Strdup,
        Self::Strndup,
    ];

    /// The standard function's name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Malloc => "malloc",
            Self::Calloc => "calloc",
            Self::Realloc => "realloc",
            Self::AlignedAlloc => "aligned_alloc",
            Self::Strdup => "strdup",
            Self::Strndup => "strndup",
        }
    }

    /// The contract a standard allocator's own name stands for.
    pub fn of_standard(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == name)
    }
}

impl fmt::Display for AllocatorContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for AllocatorContract {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::of_standard(s).ok_or_else(|| {
            format!(
                "unknown allocator contract '{s}'; allowed: {}",
                Self::ALL.map(Self::name).join(", ")
            )
        })
    }
}

/// The declarations in force: `name -> contract` for allocators and
/// `name -> freed argument (1-based)` for deallocators. Stored in the
/// bincode prescan cache, so no field may be skipped when serializing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryDeclarations {
    /// Declared allocators and the standard contract each follows.
    #[serde(default)]
    pub allocators: BTreeMap<String, AllocatorContract>,
    /// Declared deallocators and the 1-based position of the argument each
    /// frees.
    #[serde(default)]
    pub deallocators: BTreeMap<String, usize>,
}

impl MemoryDeclarations {
    /// Whether nothing is declared.
    pub fn is_empty(&self) -> bool {
        self.allocators.is_empty() && self.deallocators.is_empty()
    }

    /// Refuse a declaration that cannot mean what it says: a name that is not
    /// a C identifier, an argument position below 1, a name declared as both
    /// kinds, or a name the C library already defines, whose contract is the
    /// library's (ADR-0015) and is not the project's to restate.
    pub fn validate(&self) -> Result<()> {
        let tables = [
            (
                "[environment.allocators]",
                self.allocators.keys().collect::<Vec<_>>(),
            ),
            (
                "[environment.deallocators]",
                self.deallocators.keys().collect(),
            ),
        ];
        for (table, names) in tables {
            for name in names {
                if !is_identifier(name) {
                    bail!("{table}: '{name}' is not a C identifier");
                }
                if crate::utility::cert_c::std_functions::is_iso_c_or_posix_function(name) {
                    bail!(
                        "{table}: '{name}' is a C library function; its contract is the \
                         library's (see --libc and --list-options), not a declaration"
                    );
                }
            }
        }
        for (name, arg) in &self.deallocators {
            if *arg == 0 {
                bail!(
                    "[environment.deallocators]: '{name}' frees argument {arg}; positions \
                     count from 1"
                );
            }
            if self.allocators.contains_key(name) {
                bail!(
                    "'{name}' is declared both an allocator and a deallocator; declare a \
                     realloc-like function as an allocator with contract \"realloc\""
                );
            }
        }
        Ok(())
    }
}

fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parse a `--allocator NAME[=CONTRACT]` value; the contract defaults to
/// `malloc`.
pub fn parse_allocator_flag(value: &str) -> Result<(String, AllocatorContract)> {
    let (name, contract) = match value.split_once('=') {
        Some((n, c)) => (n.trim(), c.trim().parse().map_err(anyhow::Error::msg)?),
        None => (value.trim(), AllocatorContract::Malloc),
    };
    Ok((name.to_string(), contract))
}

/// Parse a `--deallocator NAME[=ARG]` value; the argument defaults to 1.
pub fn parse_deallocator_flag(value: &str) -> Result<(String, usize)> {
    let (name, arg) = match value.split_once('=') {
        Some((n, a)) => {
            let a = a.trim();
            let arg = a
                .parse::<usize>()
                .map_err(|_| anyhow::anyhow!("--deallocator {value}: '{a}' is not a position"))?;
            (n.trim(), arg)
        }
        None => (value.trim(), 1),
    };
    Ok((name.to_string(), arg))
}

static DECLARED: OnceLock<MemoryDeclarations> = OnceLock::new();

/// Install the declarations this process scans under. Call once, before
/// prescan: function summaries record what a wrapper around a declared hook
/// frees, so a declaration made afterwards would reach some tables and not
/// others.
///
/// # Errors
///
/// If different declarations are already in force. One process scans under
/// one set; re-declaring the identical set is fine.
pub fn declare(declarations: MemoryDeclarations) -> Result<()> {
    match DECLARED.set(declarations) {
        Ok(()) => Ok(()),
        Err(rejected) if DECLARED.get() == Some(&rejected) => Ok(()),
        Err(_) => bail!(
            "different allocator/deallocator declarations are already in force for this \
             process; one process scans under one set"
        ),
    }
}

/// The declarations in force; empty until [`declare`] installs any.
pub fn declared() -> &'static MemoryDeclarations {
    static EMPTY: OnceLock<MemoryDeclarations> = OnceLock::new();
    DECLARED
        .get()
        .unwrap_or_else(|| EMPTY.get_or_init(MemoryDeclarations::default))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decls(allocs: &[(&str, &str)], deallocs: &[(&str, usize)]) -> MemoryDeclarations {
        MemoryDeclarations {
            allocators: allocs
                .iter()
                .map(|(n, c)| (n.to_string(), c.parse().unwrap()))
                .collect(),
            deallocators: deallocs.iter().map(|(n, a)| (n.to_string(), *a)).collect(),
        }
    }

    #[test]
    fn a_platform_hook_pair_is_valid() {
        let d = decls(
            &[("MBEDTLS_PLATFORM_CALLOC_MACRO", "calloc")],
            &[("MBEDTLS_PLATFORM_FREE_MACRO", 1), ("pool_put", 2)],
        );
        d.validate().unwrap();
    }

    #[test]
    fn a_library_function_is_refused() {
        let err = decls(&[], &[("free", 2)]).validate().unwrap_err();
        assert!(err.to_string().contains("C library function"), "{err}");
        assert!(decls(&[("malloc", "calloc")], &[]).validate().is_err());
    }

    #[test]
    fn a_zero_position_a_non_identifier_and_both_kinds_are_refused() {
        assert!(decls(&[], &[("pool_put", 0)]).validate().is_err());
        assert!(decls(&[], &[("pool-put", 1)]).validate().is_err());
        assert!(decls(&[("grow", "realloc")], &[("grow", 1)])
            .validate()
            .is_err());
    }

    #[test]
    fn flags_parse_with_their_defaults() {
        assert_eq!(
            parse_deallocator_flag("HOOK").unwrap(),
            ("HOOK".to_string(), 1)
        );
        assert_eq!(
            parse_deallocator_flag("pool_put=2").unwrap(),
            ("pool_put".to_string(), 2)
        );
        assert!(parse_deallocator_flag("pool_put=x").is_err());
        assert_eq!(
            parse_allocator_flag("HOOK").unwrap(),
            ("HOOK".to_string(), AllocatorContract::Malloc)
        );
        assert_eq!(
            parse_allocator_flag("HOOK=calloc").unwrap().1,
            AllocatorContract::Calloc
        );
        assert!(parse_allocator_flag("HOOK=new").is_err());
    }

    #[test]
    fn the_tables_parse_from_toml() {
        let d: MemoryDeclarations = toml::from_str(
            "[allocators]\nHOOK_CALLOC = \"calloc\"\n[deallocators]\nHOOK_FREE = 1\n",
        )
        .unwrap();
        assert_eq!(d, decls(&[("HOOK_CALLOC", "calloc")], &[("HOOK_FREE", 1)]));
    }
}
