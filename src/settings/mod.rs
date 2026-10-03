//! Analysis settings: the policy and environment axes of ADR-0015, the
//! `default` and `strict` presets over them, and the one table of named
//! options every relaxation must appear in.
//!
//! **Policy** says what the rules require of the code (which findings are
//! reported). **Environment** says what the analyzer believes about the
//! platform the code runs on (which library and startup contracts hold).
//! The two never fold into one switch: an embedded team on a libc that
//! honors `free(NULL)` can still want the strict policy.
//!
//! [`OPTIONS`] is the record of what the default preset relaxes. The
//! `--list-options` listing and `docs/options.rst` are both rendered from it,
//! so neither can disagree with the tool. Adding a relaxation means adding a
//! row here (with its basis) and reading it through
//! [`AnalysisSettings::flag`]; nothing else needs wiring.

pub mod memory;

pub use crate::utility::cert_c::data_model::{DataModel, Fact, FactSource, IntFacts};
use anyhow::{bail, Result};
pub use memory::{AllocatorContract, MemoryDeclarations};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

/// A named preset: a value for both axes at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    /// Default policy, hosted environment: the average codebase.
    Default,
    /// Strict policy, freestanding environment: trust nothing.
    Strict,
}

/// What the rules require of the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    /// Strict minus the relaxations [`OPTIONS`] names.
    Default,
    /// Every violating line reported; no assumption credited.
    Strict,
}

/// Whether the code runs under a hosted or a freestanding implementation
/// (C11 5.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvironmentKind {
    /// A hosted implementation: the full library and `main`'s guarantees.
    Hosted,
    /// A freestanding implementation: no library semantics beyond the
    /// language.
    Freestanding,
}

/// The C library model whose documented contracts the analyzer may trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Libc {
    /// The ISO C and POSIX contracts, and nothing one libc adds. The model
    /// published benchmark figures use.
    IsoPosix,
    /// GNU C library.
    Glibc,
    /// musl libc.
    Musl,
    /// newlib.
    Newlib,
    /// picolibc.
    Picolibc,
    /// An in-house library: no contract is trusted until an override
    /// states it.
    Custom,
}

/// How an `#include` name is matched against the files on disk: a fact about
/// the toolchain that builds the code, not a contract the rules trust, so it
/// is a field of the environment rather than a row of [`OPTIONS`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IncludeNames {
    /// Byte-for-byte, as GCC and Clang on a POSIX file system see it.
    #[default]
    Exact,
    /// Ignoring case, as cl sees it: Windows looks a file name up
    /// case-insensitively unless a directory has been marked case-sensitive
    /// (Microsoft Learn, "Case sensitivity"). An exact-case entry still wins.
    CaseInsensitive,
}

/// Which axis an option belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Axis {
    /// Set by the policy.
    Policy,
    /// Set by the environment.
    Environment,
}

/// How widely an option applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// A policy relaxation many rules honor. Adding one amends ADR-0015.
    CrossCutting,
    /// A policy relaxation of one rule's checkable form.
    RuleSpecific(&'static str),
    /// A contract of the environment the code runs in.
    Contract,
}

/// Where an option's value comes from before any override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A policy option: its value under each policy.
    Policy {
        /// Value under the default policy.
        default: bool,
        /// Value under the strict policy.
        strict: bool,
    },
    /// Holds only in a hosted environment.
    Hosted,
    /// A library contract: holds when the declared libc model documents it.
    Library(&'static [Libc]),
    /// A language guarantee that only a nonconforming environment breaks:
    /// holds unless overridden.
    Language,
    /// A fact about the scanned program that only its user can declare,
    /// under either preset: false unless overridden.
    Declared,
}

/// One named option: a relaxation or a contract the analyzer may assume.
#[derive(Debug, Clone, Copy)]
pub struct OptionSpec {
    /// Stable key, as written in the manifest and `--set`.
    pub name: &'static str,
    /// The axis it belongs to.
    pub axis: Axis,
    /// How widely it applies.
    pub scope: Scope,
    /// Where its value comes from.
    pub source: Source,
    /// The oracle tag on rows this option affects (ADR-0015 Decision 5).
    pub oracle_tag: &'static str,
    /// One line on what `true` lets the analyzer assume.
    pub summary: &'static str,
    /// The evidence for it: analyzers that make the same assumption, or the
    /// clause of the standard or library documentation a contract rests on.
    pub basis: &'static str,
}

/// Every libc model that documents the ISO C allocation contracts.
const CONFORMING_LIBCS: &[Libc] = &[
    Libc::IsoPosix,
    Libc::Glibc,
    Libc::Musl,
    Libc::Newlib,
    Libc::Picolibc,
];

/// Options that enter the settings hash only when overridden away from the
/// value their source derives. Each was added after runs had already been
/// recorded, so settings that merely take the implied value keep the hash
/// those runs carry.
const HASHED_ONLY_WHEN_OVERRIDDEN: &[&str] = &["library_macros_evaluate_once"];

/// The value `o` takes from its source before any override.
fn derived_value(
    o: &OptionSpec,
    policy: Policy,
    environment: EnvironmentKind,
    libc: Option<Libc>,
) -> bool {
    match o.source {
        Source::Policy { default, strict } => match policy {
            Policy::Default => default,
            Policy::Strict => strict,
        },
        Source::Hosted => environment == EnvironmentKind::Hosted,
        Source::Library(libcs) => libc.is_some_and(|l| libcs.contains(&l)),
        Source::Language => true,
        Source::Declared => false,
    }
}

/// Every option the tool supports. The listing and the generated
/// documentation are rendered from this table.
pub static OPTIONS: &[OptionSpec] = &[
    OptionSpec {
        name: "assert_is_guard",
        axis: Axis::Policy,
        scope: Scope::CrossCutting,
        source: Source::Policy {
            default: true,
            strict: false,
        },
        oracle_tag: "assert-dominated",
        summary: "A dominating assert whose condition establishes the property is a guard, \
                  even if NDEBUG can strip it.",
        basis: "The Clang Static Analyzer, Polyspace and Coverity's models treat a live \
                assert as an assumption; CERT's EXP34-C compliant solution uses one.",
    },
    OptionSpec {
        name: "first_site_only",
        axis: Axis::Policy,
        scope: Scope::CrossCutting,
        source: Source::Policy {
            default: true,
            strict: false,
        },
        oracle_tag: "dependent-site",
        summary: "In a proof chain, only the first failing site is reported, not the sites \
                  that depend on the same missing check.",
        basis: "Mainstream path-sensitive analyzers report one missing check once.",
    },
    OptionSpec {
        name: "trust_noreturn_keyword",
        axis: Axis::Policy,
        scope: Scope::CrossCutting,
        source: Source::Policy {
            default: true,
            strict: false,
        },
        oracle_tag: "noreturn-trusted",
        summary: "A function declared _Noreturn (or <stdnoreturn.h> noreturn, or C23 \
                  [[noreturn]]) is trusted not to return; otherwise only a body verified \
                  never to return proves it.",
        basis: "C11 6.7.4p8, 7.23; C23 6.7.13.7. A GNU noreturn attribute, [[gnu::noreturn]] \
                included, is proof under neither policy.",
    },
    OptionSpec {
        name: "pre31_unknown_call_pure",
        axis: Axis::Policy,
        scope: Scope::RuleSpecific("PRE31-C"),
        source: Source::Policy {
            default: true,
            strict: false,
        },
        oracle_tag: "call-side-effect-unproven",
        summary: "PRE31-C: an unproven call, in an argument an unsafe macro may evaluate other \
                  than once, is not treated as a side effect: a call to a function with no \
                  definition in the scanned files and no library contract, a call through a \
                  pointer, strerror, inet_ntoa, strsignal, gai_strerror, getenv, gmtime and \
                  asctime (whose only effect is the static buffer they return), or a call to \
                  a scanned function that reaches one of these and nothing shown to have a \
                  side effect. A callee shown to have a side effect, in whichever scanned \
                  file it is defined, is reported either way.",
        basis: "C11 5.1.2.3p2 (which CERT quotes) makes a call a side effect only when the \
                function does one. cppcheck's assertWithSideEffect and Polyspace's MISRA C:2012 \
                Rule 13.5 flag only callees they can show are impure. clang-tidy's \
                bugprone-assert-side-effect ignores calls by default. PC-lint and Parasoft's \
                CERT_C-PRE31-c count every call, as the strict policy does.",
    },
    OptionSpec {
        name: "closed_program",
        axis: Axis::Environment,
        scope: Scope::RuleSpecific("EXP33-C"),
        source: Source::Declared,
        oracle_tag: "contract:closed_program",
        summary: "The scanned files are the whole program: nothing outside them links \
                  against it, dlopens it, or loads into it. Then a non-static, non-const \
                  global that no scanned file writes, and a non-static function that only \
                  returns a literal, are constants EXP33-C may fold to prune a branch. \
                  Undeclared, another translation unit may write the global or interpose \
                  the function, so neither is folded.",
        basis: "ADR-0011: libraries count as external, and an executable that exports its \
                symbols (-rdynamic, dlopen'ed plugins) is a library too, so in-tree writes \
                prove nothing about a global with external linkage. C11 6.2.2p2: every \
                declaration of an identifier with external linkage, in any translation \
                unit, denotes the same object. Declared by the user, never assumed: a \
                Juliet testcase set is a closed program; a library is not.",
    },
    OptionSpec {
        name: "free_null_is_noop",
        axis: Axis::Environment,
        scope: Scope::Contract,
        source: Source::Library(CONFORMING_LIBCS),
        oracle_tag: "contract:free_null_is_noop",
        summary: "free(NULL) does nothing.",
        basis: "C11 7.22.3.3p2.",
    },
    OptionSpec {
        name: "realloc_null_is_malloc",
        axis: Axis::Environment,
        scope: Scope::Contract,
        source: Source::Library(CONFORMING_LIBCS),
        oracle_tag: "contract:realloc_null_is_malloc",
        summary: "realloc(NULL, size) behaves like malloc(size).",
        basis: "C11 7.22.3.5p3.",
    },
    OptionSpec {
        name: "stdlib_noreturn",
        axis: Axis::Environment,
        scope: Scope::Contract,
        source: Source::Library(CONFORMING_LIBCS),
        oracle_tag: "contract:stdlib_noreturn",
        summary: "abort, exit, _Exit, quick_exit, longjmp, thrd_exit and POSIX _exit never \
                  return to their caller.",
        basis: "C11 7.22.4.1, 7.22.4.4, 7.22.4.5, 7.22.4.7, 7.13.2.1 and 7.26.5.5; \
                POSIX.1-2024 _exit(). A freestanding implementation need not provide \
                <stdlib.h>, <setjmp.h> or <threads.h> at all. Known limitation: two \
                cross-file summaries built by the prescan (a parameter's null state after \
                `if (!p) exit(1);`, and whether a function never returns) still credit \
                these calls whatever this option says.",
    },
    OptionSpec {
        name: "stdlib_call_effects",
        axis: Axis::Environment,
        scope: Scope::Contract,
        source: Source::Library(CONFORMING_LIBCS),
        oracle_tag: "contract:stdlib_call_effects",
        summary: "The ISO C and POSIX functions the tool lists as free of side effects \
                  (strlen, memcmp, isdigit, fabs, ntohs, ...) have none, and every other ISO C \
                  or POSIX function it knows has one (it sets errno, touches a stream, allocates, or \
                  keeps hidden state). Withdrawn, a library call is a call to an unknown \
                  function.",
        basis: "C11 7.24 and 7.4: memcmp, strcmp, strncmp, memchr, strchr, \
                strcspn, strpbrk, strrchr, strspn, strstr, strlen and the character \
                classification and case mapping functions modify no object; 7.22.1.4p8 and 7.12.1 (strtol and math functions report \
                errors through errno); CERT PRE31-C-EX1: \"even changing errno is a side \
                effect\".",
    },
    OptionSpec {
        name: "library_macros_evaluate_once",
        axis: Axis::Environment,
        scope: Scope::Contract,
        source: Source::Library(CONFORMING_LIBCS),
        oracle_tag: "contract:library_macros_evaluate_once",
        summary: "A C library function the implementation's headers define as a macro \
                  (glibc's tolower) evaluates each argument exactly once, whatever its \
                  replacement list looks like, including when a project macro hands it \
                  an argument. \"The implementation's headers\" are any defining the \
                  name outside the scanned project, so a third-party library on the \
                  search path that redefines a standard name is trusted too (a \
                  redefinition C11 7.1.3 already makes undefined). Withdrawn, such a \
                  macro is judged by its definition like any other.",
        basis: "C11 7.1.4p1: \"Any invocation of a library function that is implemented \
                as a macro shall expand to code that evaluates each of its arguments \
                exactly once\". The standard's own exceptions (the stream argument of \
                getc, putc, getwc and putwc, and assert) stay unsafe.",
    },
    OptionSpec {
        name: "main_argv_guarantees",
        axis: Axis::Environment,
        scope: Scope::Contract,
        source: Source::Hosted,
        oracle_tag: "contract:main_argv_guarantees",
        summary: "main's argc is nonnegative, argv[argc] is a null pointer, and \
                  argv[0..argc) point to strings.",
        basis: "C11 5.1.2.2.1p2, which binds hosted environments only.",
    },
    OptionSpec {
        name: "static_zero_init",
        axis: Axis::Environment,
        scope: Scope::Contract,
        source: Source::Language,
        oracle_tag: "contract:static_zero_init",
        summary: "Objects with static storage duration and no initializer are zeroed \
                  before main runs.",
        basis: "C11 6.7.9p10. Startup code that skips clearing .bss breaks it. Withdrawn, \
                a block-scope static read before its function writes it is indeterminate; \
                file-scope objects, which any function may write first, are not tracked.",
    },
];

/// Look up an option by name.
pub fn option(name: &str) -> Option<&'static OptionSpec> {
    OPTIONS.iter().find(|o| o.name == name)
}

fn allowed_names(axis: Axis) -> String {
    OPTIONS
        .iter()
        .filter(|o| o.axis == axis)
        .map(|o| o.name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The settings as a user writes them, from the manifest and the command
/// line. Every field is optional; [`AnalysisSettings::resolve`] turns it into
/// concrete values.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsConfig {
    /// A preset setting both axes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<Preset>,
    /// The policy axis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyConfig>,
    /// The environment axis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<EnvironmentConfig>,
}

/// The `[policy]` table.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Overrides the preset's policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<Policy>,
    /// Per-option overrides of policy options.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub overrides: BTreeMap<String, bool>,
}

/// The `[environment]` table.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentConfig {
    /// Overrides the preset's environment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<EnvironmentKind>,
    /// The libc model whose contracts are trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub libc: Option<Libc>,
    /// How `#include` names match files. Unset, an MSVC compile database
    /// makes it case-insensitive and anything else exact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_names: Option<IncludeNames>,
    /// The integer data model the target is built for. Unset, only what ISO
    /// C guarantees about integer widths is credited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_model: Option<DataModel>,
    /// Bits in a `short`: overrides the data model's value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_bits: Option<u32>,
    /// Bits in an `int`: overrides the data model's value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub int_bits: Option<u32>,
    /// Bits in a `long`: overrides the data model's value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub long_bits: Option<u32>,
    /// Bits in a `long long`: overrides the data model's value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub long_long_bits: Option<u32>,
    /// Bits in a pointer, `size_t`, `ptrdiff_t` and `intptr_t`: overrides the
    /// data model's value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer_bits: Option<u32>,
    /// Bits in a `wchar_t`. No data model but the Windows-only `llp64` sets it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wchar_t_bits: Option<u32>,
    /// Whether plain `char` is signed. No data model sets it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub char_signed: Option<bool>,
    /// The environment keys the command line set, for [`FactSource::Cli`]. Not
    /// part of a manifest.
    #[serde(skip)]
    pub cli: std::collections::BTreeSet<String>,
    /// Declared allocators: `name = "malloc"` (or another standard
    /// allocator whose contract the function follows). See [`memory`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub allocators: BTreeMap<String, AllocatorContract>,
    /// Declared deallocators: `name = ARG`, the 1-based position of the
    /// argument it frees. See [`memory`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub deallocators: BTreeMap<String, usize>,
    /// Per-contract overrides.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub overrides: BTreeMap<String, bool>,
}

impl EnvironmentConfig {
    /// The value a project wrote for `fact`, if any. A yes/no fact reads as
    /// 1 or 0.
    pub fn fact(&self, fact: Fact) -> Option<u32> {
        match fact {
            Fact::ShortBits => self.short_bits,
            Fact::IntBits => self.int_bits,
            Fact::LongBits => self.long_bits,
            Fact::LongLongBits => self.long_long_bits,
            Fact::PointerBits => self.pointer_bits,
            Fact::WcharBits => self.wchar_t_bits,
            Fact::CharSigned => self.char_signed.map(u32::from),
            _ => None,
        }
    }

    /// Record a project-written `value` for `fact`.
    pub fn set_fact(&mut self, fact: Fact, value: u32) {
        match fact {
            Fact::ShortBits => self.short_bits = Some(value),
            Fact::IntBits => self.int_bits = Some(value),
            Fact::LongBits => self.long_bits = Some(value),
            Fact::LongLongBits => self.long_long_bits = Some(value),
            Fact::PointerBits => self.pointer_bits = Some(value),
            Fact::WcharBits => self.wchar_t_bits = Some(value),
            Fact::CharSigned => self.char_signed = Some(value != 0),
            _ => {}
        }
    }

    /// Whether this table writes any integer fact.
    pub fn writes_a_fact(&self) -> bool {
        Fact::ALL.into_iter().any(|f| self.fact(f).is_some())
    }
}

impl SettingsConfig {
    /// Only what these settings say about the project itself rather than
    /// which preset or options it wants: its declared allocators and
    /// deallocators, and the data model of its target. A `--profile`
    /// restarts from its preset and keeps these, since a preset chooses
    /// policy and never erases what a project's own functions do or what it
    /// is built for.
    pub fn project_facts(&self) -> SettingsConfig {
        let Some(env) = &self.environment else {
            return SettingsConfig::default();
        };
        if env.allocators.is_empty()
            && env.deallocators.is_empty()
            && env.data_model.is_none()
            && !env.writes_a_fact()
        {
            return SettingsConfig::default();
        }
        let mut kept = EnvironmentConfig {
            allocators: env.allocators.clone(),
            deallocators: env.deallocators.clone(),
            data_model: env.data_model,
            ..Default::default()
        };
        for fact in Fact::ALL {
            if let Some(value) = env.fact(fact) {
                kept.set_fact(fact, value);
            }
        }
        SettingsConfig {
            environment: Some(kept),
            ..Default::default()
        }
    }

    /// Use `names` for `#include` matching unless a value is already set:
    /// what a compile database's compiler implies, which an explicit
    /// setting overrides.
    pub fn default_include_names(&mut self, names: IncludeNames) {
        self.environment
            .get_or_insert_with(Default::default)
            .include_names
            .get_or_insert(names);
    }

    /// Layer `other` over `self`: every value `other` sets wins.
    pub fn overlay(&mut self, other: &SettingsConfig) {
        if other.profile.is_some() {
            self.profile = other.profile;
        }
        if let Some(p) = &other.policy {
            let mine = self.policy.get_or_insert_with(Default::default);
            if p.level.is_some() {
                mine.level = p.level;
            }
            mine.overrides
                .extend(p.overrides.iter().map(|(k, v)| (k.clone(), *v)));
        }
        if let Some(e) = &other.environment {
            let mine = self.environment.get_or_insert_with(Default::default);
            if e.kind.is_some() {
                mine.kind = e.kind;
            }
            if e.libc.is_some() {
                mine.libc = e.libc;
            }
            if e.include_names.is_some() {
                mine.include_names = e.include_names;
            }
            if e.data_model.is_some() {
                mine.data_model = e.data_model;
                mine.cli.insert("data_model".to_string());
            }
            // `other` is the layer above: whatever it writes is the command
            // line's when it is the CLI's own settings, and `cli` remembers
            // which keys those were.
            for fact in Fact::ALL {
                if let Some(value) = e.fact(fact) {
                    mine.set_fact(fact, value);
                    mine.cli.insert(fact.key().to_string());
                }
            }
            mine.cli.extend(e.cli.iter().cloned());
            mine.allocators
                .extend(e.allocators.iter().map(|(k, v)| (k.clone(), *v)));
            mine.deallocators
                .extend(e.deallocators.iter().map(|(k, v)| (k.clone(), *v)));
            mine.overrides
                .extend(e.overrides.iter().map(|(k, v)| (k.clone(), *v)));
        }
    }

    /// Record a `NAME=VALUE` override, routed to the axis `NAME` belongs to.
    /// `data_model=MODEL` declares the environment's data model, and
    /// `int_bits=16`, `char_signed=true` and the other integer facts override
    /// what it loads.
    pub fn set(&mut self, assignment: &str) -> Result<()> {
        let Some((name, value)) = assignment.split_once('=') else {
            bail!("expected NAME=VALUE, got '{assignment}'");
        };
        let (name, value) = (name.trim(), value.trim());
        if name == "data_model" {
            let model = value
                .parse()
                .map_err(|e: String| anyhow::anyhow!("data_model: {e}"))?;
            self.environment
                .get_or_insert_with(Default::default)
                .data_model = Some(model);
            return Ok(());
        }
        if let Some(fact) = Fact::from_key(name).filter(|f| f.overridable()) {
            let number = if fact.is_flag() {
                match value {
                    "true" => 1,
                    "false" => 0,
                    _ => bail!("{name} takes true or false, got '{value}'"),
                }
            } else {
                value
                    .parse::<u32>()
                    .map_err(|_| anyhow::anyhow!("{name} takes a number of bits, got '{value}'"))?
            };
            self.environment
                .get_or_insert_with(Default::default)
                .set_fact(fact, number);
            return Ok(());
        }
        let Some(spec) = option(name) else {
            bail!(
                "unknown option '{name}'; run --list-options for the supported set ({}, and \
                 the integer facts {}, data_model)",
                OPTIONS
                    .iter()
                    .map(|o| o.name)
                    .collect::<Vec<_>>()
                    .join(", "),
                Fact::ALL
                    .into_iter()
                    .filter(|f| f.overridable())
                    .map(|f| f.key())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        };
        let value: bool = match value {
            "true" => true,
            "false" => false,
            _ => bail!("option '{name}' takes true or false, got '{value}'"),
        };
        let overrides = match spec.axis {
            Axis::Policy => &mut self.policy.get_or_insert_with(Default::default).overrides,
            Axis::Environment => {
                &mut self
                    .environment
                    .get_or_insert_with(Default::default)
                    .overrides
            }
        };
        overrides.insert(name.to_string(), value);
        Ok(())
    }
}

/// Resolved settings: one concrete value per option. Built once per run and
/// passed by reference to whatever applies an assumption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisSettings {
    /// The policy in force.
    pub policy: Policy,
    /// The environment in force.
    pub environment: EnvironmentKind,
    /// The libc model, `None` when a freestanding environment declares none.
    pub libc: Option<Libc>,
    /// How `#include` names match files.
    pub include_names: IncludeNames,
    /// The data model preset selected (`DataModel::Iso` unless declared).
    pub data_model: DataModel,
    /// The resolved integer facts: the preset's bundle under the project's
    /// own keys under the command line. What the analyses query.
    pub facts: IntFacts,
    /// The project's declared allocators and deallocators.
    pub memory: MemoryDeclarations,
    /// The path globs whose files the cross-file prescan does not read
    /// (`--exclude-all` and `--prescan-exclude`, with their manifest keys),
    /// sorted and deduplicated. What a summary, a macro's alternatives or a
    /// noreturn set can hold depends on them.
    pub prescan_scope: Vec<String>,
    values: BTreeMap<&'static str, bool>,
}

impl Default for AnalysisSettings {
    fn default() -> Self {
        Self::preset(Preset::Default)
    }
}

impl AnalysisSettings {
    /// The settings a preset names, with no overrides.
    pub fn preset(preset: Preset) -> Self {
        Self::resolve(&SettingsConfig {
            profile: Some(preset),
            ..Default::default()
        })
        .expect("a bare preset always resolves")
    }

    /// Resolve `config`: the preset, then each axis's own setting, then the
    /// libc model's contracts, then per-option overrides. An override naming
    /// an unknown option, or an option of the other axis, is refused by name.
    pub fn resolve(config: &SettingsConfig) -> Result<Self> {
        let preset = config.profile.unwrap_or(Preset::Default);
        let (mut policy, mut environment) = match preset {
            Preset::Default => (Policy::Default, EnvironmentKind::Hosted),
            Preset::Strict => (Policy::Strict, EnvironmentKind::Freestanding),
        };
        let mut libc = None;
        let mut include_names = IncludeNames::default();
        let mut data_model = DataModel::default();
        let mut facts_config: Option<&EnvironmentConfig> = None;
        let mut memory = MemoryDeclarations::default();
        if let Some(p) = &config.policy {
            policy = p.level.unwrap_or(policy);
        }
        if let Some(e) = &config.environment {
            environment = e.kind.unwrap_or(environment);
            libc = e.libc;
            include_names = e.include_names.unwrap_or_default();
            data_model = e.data_model.unwrap_or_default();
            facts_config = Some(e);
            memory = MemoryDeclarations {
                allocators: e.allocators.clone(),
                deallocators: e.deallocators.clone(),
            };
            memory.validate()?;
        }
        // A hosted implementation provides the standard library, so its
        // contracts hold unless a model says otherwise; a freestanding one
        // provides none unless a library is declared.
        if libc.is_none() && environment == EnvironmentKind::Hosted {
            libc = Some(Libc::IsoPosix);
        }

        let mut values = BTreeMap::new();
        for o in OPTIONS {
            values.insert(o.name, derived_value(o, policy, environment, libc));
        }

        let overrides = [
            (
                Axis::Policy,
                "[policy.overrides]",
                config.policy.as_ref().map(|p| &p.overrides),
            ),
            (
                Axis::Environment,
                "[environment.overrides]",
                config.environment.as_ref().map(|e| &e.overrides),
            ),
        ];
        for (axis, table, map) in overrides {
            for (name, value) in map.into_iter().flatten() {
                match option(name) {
                    Some(spec) if spec.axis == axis => {
                        values.insert(spec.name, *value);
                    }
                    Some(_) => bail!(
                        "option '{name}' does not belong in {table}; that table takes: {}",
                        allowed_names(axis)
                    ),
                    None => bail!(
                        "unknown option '{name}' in {table}; allowed: {}",
                        allowed_names(axis)
                    ),
                }
            }
        }

        // The preset's bundle, then each fact the project wrote, then each
        // the command line wrote: a higher layer replaces a lower one
        // whatever the order of the lines.
        let mut facts = IntFacts::preset(data_model);
        if let Some(e) = facts_config {
            for fact in Fact::ALL {
                if let Some(value) = e.fact(fact) {
                    let source = if e.cli.contains(fact.key()) {
                        FactSource::Cli
                    } else if facts.get(fact) == Some(value) {
                        // A line that only repeats what the preset loads (as
                        // a generated configuration writes them) declares
                        // nothing: the fact stays the preset's, and the
                        // settings hash stays the preset's too.
                        continue;
                    } else {
                        FactSource::Config
                    };
                    facts.set(fact, value, source);
                }
            }
        }
        let problems = facts.problems();
        if !problems.is_empty() {
            bail!("{}", problems.join("\n"));
        }

        Ok(Self {
            policy,
            environment,
            libc,
            include_names,
            data_model,
            facts,
            memory,
            prescan_scope: Vec::new(),
            values,
        })
    }

    /// Record the path globs the prescan leaves out, sorted and
    /// deduplicated so the same scope always names the same settings.
    pub fn set_prescan_scope(&mut self, globs: impl IntoIterator<Item = String>) {
        let mut scope: Vec<String> = globs.into_iter().collect();
        scope.sort();
        scope.dedup();
        self.prescan_scope = scope;
    }

    /// The value of the option `name`.
    ///
    /// # Panics
    /// If `name` is not in [`OPTIONS`]: a consumer reading an option the
    /// table does not declare is a bug, never a configuration error.
    pub fn flag(&self, name: &str) -> bool {
        match self.values.get(name) {
            Some(v) => *v,
            None => panic!("option '{name}' is not declared in settings::OPTIONS"),
        }
    }

    /// The preset these settings equal, if any. A preset says nothing about
    /// how `#include` names match, the data model, which functions a
    /// project declares or which files the prescan reads, so those fields
    /// are not compared.
    pub fn matching_preset(&self) -> Option<Preset> {
        [Preset::Default, Preset::Strict].into_iter().find(|p| {
            *self
                == Self {
                    include_names: self.include_names,
                    data_model: self.data_model,
                    facts: self.facts,
                    memory: self.memory.clone(),
                    prescan_scope: self.prescan_scope.clone(),
                    ..Self::preset(*p)
                }
        })
    }

    /// Every option's resolved value, in table order.
    pub fn values(&self) -> impl Iterator<Item = (&'static str, bool)> + '_ {
        OPTIONS.iter().map(|o| (o.name, self.values[o.name]))
    }

    /// The settings as a JSON object, for a report's run metadata: the
    /// resolved values plus their [`settings_hash`](Self::settings_hash).
    pub fn to_json(&self) -> serde_json::Value {
        let mut v = self.identity_json();
        v["hash"] = serde_json::Value::String(self.settings_hash());
        v
    }

    /// The settings as canonical JSON: every object's keys sorted, no
    /// whitespace. Stable across builds and serde feature sets, so equal
    /// settings always serialize to equal bytes.
    pub fn canonical_json(&self) -> String {
        canonical(&self.identity_json())
    }

    /// SHA-256 (hex) of [`canonical_json`](Self::canonical_json). Names the
    /// settings a run scanned under: benchmark run ids carry its first 12
    /// characters, and a report carries all of it. Every option the table
    /// knows is part of it, so adding an option changes every hash, except
    /// one in [`HASHED_ONLY_WHEN_OVERRIDDEN`], which counts only when an
    /// override departs from what the preset, policy, environment and libc
    /// imply.
    pub fn settings_hash(&self) -> String {
        crate::utility::hash::sha256_hex(self.canonical_json().as_bytes())
    }

    fn identity_json(&self) -> serde_json::Value {
        let options: serde_json::Map<String, serde_json::Value> = OPTIONS
            .iter()
            .filter(|o| {
                !HASHED_ONLY_WHEN_OVERRIDDEN.contains(&o.name)
                    || self.values[o.name]
                        != derived_value(o, self.policy, self.environment, self.libc)
            })
            .map(|o| {
                (
                    o.name.to_string(),
                    serde_json::Value::Bool(self.values[o.name]),
                )
            })
            .collect();
        let mut identity = serde_json::json!({
            "preset": self.matching_preset(),
            "policy": self.policy,
            "environment": self.environment,
            "libc": self.libc,
            "options": options,
        });
        // Present only when it departs from exact matching, so the settings
        // every run scanned under before the field existed keep their hash.
        if self.include_names != IncludeNames::Exact {
            identity["include_names"] = serde_json::json!(self.include_names);
        }
        // Likewise only when a model is declared.
        if self.data_model != DataModel::Iso {
            identity["data_model"] = serde_json::json!(self.data_model);
        }
        // Every fact the project or the command line declared, under its own
        // key; a preset's bundle is already named by `data_model`.
        for (fact, value) in self.facts.declared() {
            identity[fact.key()] = if fact.is_flag() {
                serde_json::json!(value != 0)
            } else {
                serde_json::json!(value)
            };
        }
        // Likewise present only when something is declared.
        if !self.memory.allocators.is_empty() {
            identity["allocators"] = serde_json::json!(self.memory.allocators);
        }
        if !self.memory.deallocators.is_empty() {
            identity["deallocators"] = serde_json::json!(self.memory.deallocators);
        }
        // Likewise present only when the prescan leaves files out.
        if !self.prescan_scope.is_empty() {
            identity["prescan_scope"] = serde_json::json!(self.prescan_scope);
        }
        identity
    }
}

macro_rules! display_via_serde {
    ($($t:ty),*) => {$(
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match serde_json::to_value(self) {
                    Ok(serde_json::Value::String(s)) => f.write_str(&s),
                    _ => Err(fmt::Error),
                }
            }
        }

        impl FromStr for $t {
            type Err = String;

            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                serde_json::from_value(serde_json::Value::String(s.to_string()))
                    .map_err(|_| format!("invalid value '{s}'"))
            }
        }
    )*};
}

display_via_serde!(
    Preset,
    Policy,
    EnvironmentKind,
    Libc,
    IncludeNames,
    DataModel
);

/// `v` serialized with every object's keys in sorted order and no
/// whitespace, whatever order the map preserved.
fn canonical(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let fields: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::Value::String(k.clone()),
                        canonical(&map[k])
                    )
                })
                .collect();
            format!("{{{}}}", fields.join(","))
        }
        serde_json::Value::Array(items) => {
            format!(
                "[{}]",
                items.iter().map(canonical).collect::<Vec<_>>().join(",")
            )
        }
        other => other.to_string(),
    }
}

fn scope_label(scope: Scope) -> String {
    match scope {
        Scope::CrossCutting => "cross-cutting".to_string(),
        Scope::RuleSpecific(rule) => rule.to_string(),
        Scope::Contract => "contract".to_string(),
    }
}

fn axis_label(axis: Axis) -> &'static str {
    match axis {
        Axis::Policy => "policy",
        Axis::Environment => "environment",
    }
}

/// One line of a generated configuration: `key = value`, commented out when
/// it is the built-in default, with `note` after it.
fn config_entry(out: &mut String, active: bool, key: &str, value: &str, note: &str) {
    if !active {
        out.push_str("# ");
    }
    out.push_str(&format!("{key} = {value}"));
    if !note.is_empty() {
        out.push_str(&format!("  # {note}"));
    }
    out.push('\n');
}

/// The value a commented-out example for `fact` shows: the first preset that
/// loads it, or the ISO minimum.
fn example_fact_value(fact: Fact) -> String {
    let loaded = DataModel::ALL
        .into_iter()
        .find_map(|m| m.bundle().iter().find(|(f, _)| *f == fact).map(|(_, v)| *v));
    match (loaded, fact.is_flag()) {
        (_, true) => "true".to_string(),
        (Some(v), false) => v.to_string(),
        (None, false) => fact.minimum_bits().unwrap_or(0).to_string(),
    }
}

/// The settings half of a generated configuration (`--write-config`): the
/// `profile` key and the `[policy]` and `[environment]` tables, every key
/// with a one-line description. A key at its built-in default is commented
/// out; one that departs from it is an active line, and a fact a data-model
/// preset loads says which. Built from the same tables as `--list-options`
/// and validation ([`OPTIONS`], [`Fact::ALL`], [`DataModel::bundle`]), so it
/// cannot drift from them, and it resolves to exactly `current`.
pub fn render_config_settings(current: &AnalysisSettings) -> String {
    let profile = if current.policy == Policy::Strict {
        Preset::Strict
    } else {
        Preset::Default
    };
    let (base_policy, base_environment) = match profile {
        Preset::Default => (Policy::Default, EnvironmentKind::Hosted),
        Preset::Strict => (Policy::Strict, EnvironmentKind::Freestanding),
    };
    let mut out = String::new();
    out.push_str("# A preset that sets both axes: \"default\" or \"strict\".\n");
    config_entry(
        &mut out,
        profile != Preset::Default,
        "profile",
        &format!("\"{profile}\""),
        "",
    );

    out.push_str("\n[policy]\n# What the rules require of the code: \"default\" or \"strict\".\n");
    config_entry(
        &mut out,
        current.policy != base_policy,
        "level",
        &format!("\"{}\"", current.policy),
        "",
    );
    let option_table = |out: &mut String, axis: Axis| {
        for o in OPTIONS.iter().filter(|o| o.axis == axis) {
            let value = current.flag(o.name);
            let departs =
                value != derived_value(o, current.policy, current.environment, current.libc);
            out.push_str(&format!("# {}\n", o.summary));
            config_entry(out, departs, o.name, &value.to_string(), "");
        }
    };
    out.push_str("\n[policy.overrides]\n");
    option_table(&mut out, Axis::Policy);

    out.push_str(
        "\n[environment]\n# \"hosted\" (the full standard library) or \"freestanding\".\n",
    );
    config_entry(
        &mut out,
        current.environment != base_environment,
        "kind",
        &format!("\"{}\"", current.environment),
        "",
    );
    let implied_libc = (current.environment == EnvironmentKind::Hosted).then_some(Libc::IsoPosix);
    out.push_str(
        "# The C library whose documented contracts are trusted: iso-posix, glibc, musl, newlib,\n\
         # picolibc or custom. Unset: iso-posix when hosted, none when freestanding.\n",
    );
    config_entry(
        &mut out,
        current.libc != implied_libc,
        "libc",
        &format!("\"{}\"", current.libc.unwrap_or(Libc::IsoPosix)),
        "",
    );
    out.push_str("# How #include names match files: \"exact\" or \"case-insensitive\".\n");
    config_entry(
        &mut out,
        current.include_names != IncludeNames::Exact,
        "include_names",
        &format!("\"{}\"", current.include_names),
        "",
    );
    out.push_str(&format!(
        "# The integer data model preset: {}. Unset (iso), only what ISO C guarantees is credited.\n",
        DataModel::ALL.map(|m| m.name()).join(", ")
    ));
    config_entry(
        &mut out,
        current.data_model != DataModel::Iso,
        "data_model",
        &format!("\"{}\"", current.data_model),
        "",
    );
    out.push_str(
        "# Integer facts: the preset loads some; a key here overrides it (and must stay at or\n\
         # above the ISO minimum and in rank order). Unset facts are unknown to the analysis.\n",
    );
    for fact in Fact::ALL.into_iter().filter(|f| f.overridable()) {
        out.push_str(&format!("# {}\n", fact.description()));
        let value = current.facts.get(fact);
        let text = value.map(|v| {
            if fact.is_flag() {
                (v != 0).to_string()
            } else {
                v.to_string()
            }
        });
        match (text, current.facts.source(fact)) {
            (Some(text), FactSource::Preset(m)) => {
                config_entry(
                    &mut out,
                    true,
                    fact.key(),
                    &text,
                    &format!("from preset: {m}", m = m.name()),
                );
            }
            (Some(text), FactSource::Cli) => {
                config_entry(&mut out, true, fact.key(), &text, "set on the command line");
            }
            (Some(text), _) => config_entry(&mut out, true, fact.key(), &text, "declared"),
            (None, _) => {
                let note = match fact.minimum_bits().filter(|_| fact.has_floor()) {
                    Some(min) => {
                        format!("unknown unless declared (ISO guarantees at least {min} bits)")
                    }
                    None => "unknown unless declared".to_string(),
                };
                config_entry(
                    &mut out,
                    false,
                    fact.key(),
                    &example_fact_value(fact),
                    &note,
                );
            }
        }
    }

    out.push_str("\n[environment.overrides]\n");
    option_table(&mut out, Axis::Environment);

    out.push_str(
        "\n# Functions that allocate: NAME = \"malloc\" (or calloc, realloc, ...).\n[environment.allocators]\n",
    );
    if current.memory.allocators.is_empty() {
        out.push_str("# my_alloc = \"malloc\"\n");
    }
    for (name, contract) in &current.memory.allocators {
        out.push_str(&format!("{name:?} = \"{contract}\"\n"));
    }
    out.push_str(
        "\n# Functions that free: NAME = ARG, the 1-based position of the freed argument.\n[environment.deallocators]\n",
    );
    if current.memory.deallocators.is_empty() {
        out.push_str("# my_free = 1\n");
    }
    for (name, arg) in &current.memory.deallocators {
        out.push_str(&format!("{name:?} = {arg}\n"));
    }
    out
}

/// One resolved integer fact as `--list-options` shows it.
pub struct FactRow {
    /// The `[environment]` key.
    pub key: &'static str,
    /// The value, `>= N` for a fact only the ISO floor bounds, or `unknown`.
    pub value: String,
    /// `cli`, `config`, `preset:NAME`, `iso-floor` or `unknown`.
    pub source: String,
    /// What the fact is.
    pub description: &'static str,
    /// Whether a project may write it.
    pub overridable: bool,
}

/// Every integer fact with its value and where it came from, in listing
/// order: what a scan under `current` will credit, line by line.
pub fn fact_rows(current: &AnalysisSettings) -> Vec<FactRow> {
    Fact::ALL
        .into_iter()
        .map(|fact| {
            let (value, source) = match current.facts.get(fact) {
                Some(v) if fact.is_flag() => {
                    ((v != 0).to_string(), current.facts.source(fact).label())
                }
                Some(v) => (v.to_string(), current.facts.source(fact).label()),
                None if fact.has_floor() => (
                    format!(">= {}", fact.minimum_bits().unwrap_or(0)),
                    "iso-floor".to_string(),
                ),
                None => ("unknown".to_string(), "unknown".to_string()),
            };
            FactRow {
                key: fact.key(),
                value,
                source,
                description: fact.description(),
                overridable: fact.overridable(),
            }
        })
        .collect()
}

/// The option listing as plain text, with each preset's value and the
/// value `current` resolves to.
pub fn render_text(current: &AnalysisSettings) -> String {
    let default = AnalysisSettings::preset(Preset::Default);
    let strict = AnalysisSettings::preset(Preset::Strict);
    let mut out = format!(
        "Current: policy={}, environment={}, libc={}, include_names={}, data_model={}\n\n",
        current.policy,
        current.environment,
        current
            .libc
            .map_or_else(|| "none".to_string(), |l| l.to_string()),
        current.include_names,
        current.data_model,
    );
    // Each integer fact the project or the command line declared on top of
    // the preset, so the line names everything that is not a default.
    let declared: Vec<String> = current
        .facts
        .declared()
        .map(|(fact, value)| {
            if fact.is_flag() {
                format!("{}={}", fact.key(), value != 0)
            } else {
                format!("{}={value}", fact.key())
            }
        })
        .collect();
    if !declared.is_empty() {
        out.pop();
        out.pop();
        out.push_str(&format!(", {}\n\n", declared.join(", ")));
    }
    for (name, contract) in &current.memory.allocators {
        out.push_str(&format!("Declared allocator: {name} (as {contract})\n"));
    }
    for (name, arg) in &current.memory.deallocators {
        out.push_str(&format!(
            "Declared deallocator: {name} (frees argument {arg})\n"
        ));
    }
    if !current.memory.is_empty() {
        out.push('\n');
    }
    out.push_str(&format!(
        "{:<24} {:<12} {:<14} {:>7} {:>7} {:>7}\n",
        "OPTION", "AXIS", "SCOPE", "default", "strict", "current"
    ));
    for o in OPTIONS {
        out.push_str(&format!(
            "{:<24} {:<12} {:<14} {:>7} {:>7} {:>7}\n    {}\n    Basis: {}\n",
            o.name,
            axis_label(o.axis),
            scope_label(o.scope),
            default.flag(o.name),
            strict.flag(o.name),
            current.flag(o.name),
            o.summary,
            o.basis,
        ));
    }
    out.push_str(&format!(
        "\nINTEGER FACTS (preset {}; precedence: cli, config, preset, iso-floor)\n",
        current.data_model
    ));
    out.push_str(&format!(
        "{:<20} {:<9} {:<14} {}\n",
        "FACT", "VALUE", "SOURCE", ""
    ));
    for row in fact_rows(current) {
        out.push_str(&format!(
            "{:<20} {:<9} {:<14} {}{}\n",
            row.key,
            row.value,
            row.source,
            row.description,
            if row.overridable {
                ""
            } else {
                " (preset only)"
            }
        ));
    }
    out
}

/// The option listing as JSON, with each preset's value and the value
/// `current` resolves to.
pub fn render_json(current: &AnalysisSettings) -> serde_json::Value {
    let default = AnalysisSettings::preset(Preset::Default);
    let strict = AnalysisSettings::preset(Preset::Strict);
    let options: Vec<serde_json::Value> = OPTIONS
        .iter()
        .map(|o| {
            serde_json::json!({
                "name": o.name,
                "axis": axis_label(o.axis),
                "scope": scope_label(o.scope),
                "oracle_tag": o.oracle_tag,
                "default": default.flag(o.name),
                "strict": strict.flag(o.name),
                "current": current.flag(o.name),
                "summary": o.summary,
                "basis": o.basis,
            })
        })
        .collect();
    let facts: Vec<serde_json::Value> = fact_rows(current)
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "key": r.key,
                "value": r.value,
                "source": r.source,
                "description": r.description,
                "overridable": r.overridable,
            })
        })
        .collect();
    serde_json::json!({ "current": current.to_json(), "options": options, "facts": facts })
}

/// `docs/options.rst`, generated. A test fails when the committed file
/// differs, so the documentation cannot drift from the table.
pub fn render_rst() -> String {
    let default = AnalysisSettings::preset(Preset::Default);
    let strict = AnalysisSettings::preset(Preset::Strict);
    let mut out = String::from(
        "..\n   Generated by `aurora-lint --list-options rst`. Do not edit by hand:\n   \
         change the table in src/settings/mod.rs and regenerate.\n\n\
         Policy and Environment Options\n\
         ==============================\n\n\
         Every assumption the analyzer can be told to make or drop is a named option\n\
         below, with its value under each preset. This list is the complete record of\n\
         what the default preset relaxes. See :doc:`configuration` for how to set\n\
         them.\n\n\
         - The **default** preset is ``policy = default`` with a ``hosted``\n  \
         environment and the ISO C + POSIX library model.\n\
         - The **strict** preset is ``policy = strict`` with a ``freestanding``\n  \
         environment and no library model.\n\n",
    );
    for (axis, title) in [
        (Axis::Policy, "Policy options"),
        (Axis::Environment, "Environment contracts"),
    ] {
        out.push_str(title);
        out.push('\n');
        out.push_str(&"-".repeat(title.len()));
        out.push_str("\n\n");
        for o in OPTIONS.iter().filter(|o| o.axis == axis) {
            out.push_str(&format!("``{}``\n", o.name));
            out.push_str(&format!("   {}\n\n", o.summary));
            out.push_str(&format!(
                "   - Default preset: ``{}``; strict preset: ``{}``\n",
                default.flag(o.name),
                strict.flag(o.name)
            ));
            out.push_str(&format!("   - Scope: {}\n", scope_label(o.scope)));
            out.push_str(&format!("   - Oracle tag: ``{}``\n", o.oracle_tag));
            out.push_str(&format!("   - Basis: {}\n\n", o.basis));
        }
    }
    out.push_str(
        "Toolchain\n\
         ---------\n\n\
         ``include_names``\n   \
         How an ``#include`` name is matched against the files on disk: ``exact``, or\n   \
         ``case-insensitive`` as cl does on Windows, where an exact-case entry still\n   \
         wins. It is a fact about the toolchain rather than an assumption the rules\n   \
         trust, so neither preset sets it and it carries no oracle tag. Unset, it is\n   \
         ``case-insensitive`` when ``--compile-commands`` names a cl or clang-cl build\n   \
         and ``exact`` otherwise; the scanning host's own file system never decides it.\n\n   \
         - Set with ``[environment] include_names`` or ``--include-names``\n   \
         - Part of the settings hash only when ``case-insensitive``\n   \
         - Basis: Windows looks file names up case-insensitively unless a directory\n     \
         is marked case-sensitive (Microsoft Learn, \"Case sensitivity\").\n\n\
         ``data_model``\n   \
         How wide the integer types are: ``iso``, the default, credits only what ISO C\n   \
         guarantees (``CHAR_BIT`` at least 8, ``short`` and ``int`` at least 16 bits,\n   \
         ``long`` at least 32, ``long long`` at least 64, and the exact width of\n   \
         ``int32_t`` and its kind); ``ilp32``, ``lp64`` or ``llp64`` declares the\n   \
         target's model, so ``INT_MAX``, ``sizeof(long)`` and the like have their\n   \
         values there. Under ``iso`` a limit such as ``INT_MAX`` is unknown, a value is\n   \
         proven to fit a type only within the guaranteed range, and a defect that\n   \
         occurs on some conforming width is reported. Neither preset sets it.\n\n   \
         - Set with ``[environment] data_model`` or ``--data-model``\n   \
         - Part of the settings hash only when not ``iso``\n   \
         - Basis: C11 5.2.4.2.1 (minimum magnitudes), 6.3.1.1 (rank order) and\n     \
         7.20.1.1 (exact-width types); integer widths are otherwise\n     \
         implementation-defined.\n",
    );
    out.push_str(
        "\nDeclared memory functions\n\
         -------------------------\n\n\
         ``allocators`` and ``deallocators``\n   \
         A function the scan has no body for (a platform hook supplied at build time,\n   \
         or a library outside the scanned tree) cannot be proven to allocate or to\n   \
         free. A project declares what such a function does: a deallocator frees\n   \
         the argument its position names (counting from 1), and an allocator\n   \
         returns fresh memory under the contract of the standard\n   \
         allocator it names (``malloc``, ``calloc``, ``realloc``, ``aligned_alloc``,\n   \
         ``strdup`` or ``strndup``). A ``realloc``-like allocator also releases the\n   \
         block its first argument points at. The memory-lifetime rules (MEM00-C,\n   \
         MEM01-C, MEM03-C, MEM30-C, MEM31-C, MEM34-C) and the function summaries\n   \
         that credit a wrapper with what it frees read the declarations, whichever\n   \
         way they cut: a free through a declared hook excuses a leak and makes a\n   \
         second free a double free. A rule that only asks whether a call allocates\n   \
         at all counts a declared allocator too. Null-state, unchecked-result and\n   \
         allocation-size checks still recognize the standard names only. A function\n   \
         whose body the scan reads needs no declaration, and a C library function\n   \
         cannot be declared, since its contract is the library's.\n\n   \
         - Set with ``[environment.allocators]`` ``NAME = \"CONTRACT\"`` and\n     \
         ``[environment.deallocators]`` ``NAME = ARG``, or ``--allocator\n     \
         NAME[=CONTRACT]`` (default ``malloc``) and ``--deallocator NAME[=ARG]``\n     \
         (default 1)\n   \
         - Part of the settings hash only when something is declared\n   \
         - Basis: the project's own statement of its environment (ADR-0001, ADR-0015)\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_names(preset: Preset, names: Option<IncludeNames>) -> AnalysisSettings {
        AnalysisSettings::resolve(&SettingsConfig {
            profile: Some(preset),
            environment: names.map(|n| EnvironmentConfig {
                include_names: Some(n),
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap()
    }

    fn with_memory(toml_env: &str) -> Result<AnalysisSettings> {
        let config: SettingsConfig = toml::from_str(toml_env).unwrap();
        AnalysisSettings::resolve(&config)
    }

    #[test]
    fn no_declarations_leave_the_preset_hash_and_one_moves_it() {
        let none = with_memory("[environment]\n").unwrap();
        assert_eq!(
            none.settings_hash(),
            AnalysisSettings::preset(Preset::Default).settings_hash()
        );
        assert!(none.to_json()["deallocators"].is_null());
        let hook = with_memory(
            "[environment.deallocators]\nMBEDTLS_PLATFORM_FREE_MACRO = 1\n\
             [environment.allocators]\nMBEDTLS_PLATFORM_CALLOC_MACRO = \"calloc\"\n",
        )
        .unwrap();
        assert_ne!(hook.settings_hash(), none.settings_hash());
        assert_eq!(
            hook.to_json()["deallocators"]["MBEDTLS_PLATFORM_FREE_MACRO"],
            1
        );
        assert_eq!(
            hook.to_json()["allocators"]["MBEDTLS_PLATFORM_CALLOC_MACRO"],
            "calloc"
        );
        // A declaration is a project fact, not a departure from the preset.
        assert_eq!(hook.matching_preset(), Some(Preset::Default));
        let other =
            with_memory("[environment.deallocators]\nMBEDTLS_PLATFORM_FREE_MACRO = 2\n").unwrap();
        assert_ne!(other.settings_hash(), hook.settings_hash());
    }

    #[test]
    fn an_invalid_declaration_is_refused_by_resolve() {
        assert!(with_memory("[environment.deallocators]\nfree = 1\n").is_err());
        assert!(
            toml::from_str::<SettingsConfig>("[environment.allocators]\nhook = \"new\"\n").is_err()
        );
    }

    #[test]
    fn declarations_overlay_by_name() {
        let mut base: SettingsConfig =
            toml::from_str("[environment.deallocators]\na_put = 1\nb_put = 1\n").unwrap();
        let cli: SettingsConfig =
            toml::from_str("[environment.deallocators]\nb_put = 2\n").unwrap();
        base.overlay(&cli);
        let s = AnalysisSettings::resolve(&base).unwrap();
        assert_eq!(s.memory.deallocators["a_put"], 1);
        assert_eq!(s.memory.deallocators["b_put"], 2);
    }

    #[test]
    fn a_profile_keeps_the_projects_declarations_and_nothing_else() {
        let manifest: SettingsConfig = toml::from_str(
            "[policy]\nlevel = \"strict\"\n\
             [environment]\nlibc = \"musl\"\n\
             [environment.deallocators]\nhook_put = 2\n\
             [environment.allocators]\nhook_take = \"calloc\"\n",
        )
        .unwrap();
        let facts = manifest.project_facts();
        assert!(facts.profile.is_none() && facts.policy.is_none());
        let env = facts.environment.unwrap();
        assert_eq!(env.libc, None);
        assert_eq!(env.deallocators["hook_put"], 2);
        assert_eq!(env.allocators["hook_take"], AllocatorContract::Calloc);
        let bare: SettingsConfig = toml::from_str("[environment]\nlibc = \"musl\"\n").unwrap();
        assert_eq!(bare.project_facts(), SettingsConfig::default());
        let target: SettingsConfig =
            toml::from_str("[environment]\nlibc = \"musl\"\ndata_model = \"lp64\"\n").unwrap();
        let facts = target.project_facts().environment.unwrap();
        assert_eq!(facts.data_model, Some(DataModel::Lp64));
        assert_eq!(facts.libc, None);
    }

    #[test]
    fn exact_include_names_leave_every_preset_hash_as_it_was() {
        // The presets' hashes with the current option table (`closed_program`
        // added a declared option, which moved both). Benchmark run ids carry
        // them, so exact include-name matching must not move them.
        assert_eq!(
            AnalysisSettings::preset(Preset::Default).settings_hash(),
            "6a42bd4cf1e02bd610c081ad24a69ebfc4a214e67a7f338449fd9651ddf24c8f"
        );
        assert_eq!(
            AnalysisSettings::preset(Preset::Strict).settings_hash(),
            "b15a42e2ed2094bb968fc6ff764429d5f3e598d0103e91ab3ff660286dc648f9"
        );
        assert_eq!(
            with_names(Preset::Default, Some(IncludeNames::Exact)).settings_hash(),
            AnalysisSettings::preset(Preset::Default).settings_hash()
        );
    }

    #[test]
    fn a_late_option_moves_the_hash_only_when_overridden() {
        let with = |preset: Preset, value: bool| {
            let mut config = SettingsConfig {
                profile: Some(preset),
                ..Default::default()
            };
            config
                .set(&format!("library_macros_evaluate_once={value}"))
                .unwrap();
            AnalysisSettings::resolve(&config).unwrap()
        };
        for preset in [Preset::Default, Preset::Strict] {
            let base = AnalysisSettings::preset(preset);
            let implied = base.flag("library_macros_evaluate_once");
            assert_eq!(with(preset, implied).settings_hash(), base.settings_hash());
            let overridden = with(preset, !implied);
            assert_ne!(overridden.settings_hash(), base.settings_hash());
            assert_eq!(
                overridden.to_json()["options"]["library_macros_evaluate_once"],
                !implied
            );
        }
    }

    #[test]
    fn case_insensitive_include_names_are_named_and_hashed_but_keep_the_preset() {
        let s = with_names(Preset::Default, Some(IncludeNames::CaseInsensitive));
        assert_eq!(s.include_names, IncludeNames::CaseInsensitive);
        assert_eq!(s.matching_preset(), Some(Preset::Default));
        assert_ne!(
            s.settings_hash(),
            AnalysisSettings::preset(Preset::Default).settings_hash()
        );
        assert_eq!(s.to_json()["include_names"], "case-insensitive");
        assert!(AnalysisSettings::preset(Preset::Default).to_json()["include_names"].is_null());
    }

    #[test]
    fn a_prescan_scope_is_named_and_hashed_but_keeps_the_preset() {
        let mut s = AnalysisSettings::preset(Preset::Default);
        let before = s.settings_hash();
        s.set_prescan_scope(Vec::new());
        assert_eq!(s.settings_hash(), before);
        assert!(s.to_json()["prescan_scope"].is_null());

        s.set_prescan_scope([
            "tests/**".to_string(),
            "docs/**".to_string(),
            "tests/**".to_string(),
        ]);
        assert_eq!(s.prescan_scope, ["docs/**", "tests/**"]);
        assert_eq!(s.matching_preset(), Some(Preset::Default));
        assert_ne!(s.settings_hash(), before);
        assert_eq!(s.to_json()["prescan_scope"][1], "tests/**");
    }

    #[test]
    fn a_compile_database_default_yields_to_an_explicit_setting() {
        let mut implied = SettingsConfig::default();
        implied.default_include_names(IncludeNames::CaseInsensitive);
        assert_eq!(
            AnalysisSettings::resolve(&implied).unwrap().include_names,
            IncludeNames::CaseInsensitive
        );

        let mut explicit = SettingsConfig {
            environment: Some(EnvironmentConfig {
                include_names: Some(IncludeNames::Exact),
                ..Default::default()
            }),
            ..Default::default()
        };
        explicit.default_include_names(IncludeNames::CaseInsensitive);
        assert_eq!(
            AnalysisSettings::resolve(&explicit).unwrap().include_names,
            IncludeNames::Exact
        );
    }

    #[test]
    fn include_names_parse_from_the_manifest_and_overlay() {
        let config: SettingsConfig =
            toml::from_str("[environment]\ninclude_names = \"case-insensitive\"\n").unwrap();
        assert_eq!(
            AnalysisSettings::resolve(&config).unwrap().include_names,
            IncludeNames::CaseInsensitive
        );
        let mut base = config.clone();
        base.overlay(&SettingsConfig {
            environment: Some(EnvironmentConfig {
                include_names: Some(IncludeNames::Exact),
                ..Default::default()
            }),
            ..Default::default()
        });
        assert_eq!(
            AnalysisSettings::resolve(&base).unwrap().include_names,
            IncludeNames::Exact
        );
        assert!("exact".parse::<IncludeNames>().is_ok());
        assert!("insensitive".parse::<IncludeNames>().is_err());
    }

    #[test]
    fn only_a_declared_data_model_is_named_and_hashed() {
        let with = |model: Option<DataModel>| {
            AnalysisSettings::resolve(&SettingsConfig {
                environment: Some(EnvironmentConfig {
                    data_model: model,
                    ..Default::default()
                }),
                ..Default::default()
            })
            .unwrap()
        };
        let base = AnalysisSettings::preset(Preset::Default);
        assert_eq!(base.data_model, DataModel::Iso);
        let iso = with(Some(DataModel::Iso));
        assert_eq!(iso.settings_hash(), base.settings_hash());
        assert!(iso.to_json()["data_model"].is_null());
        let lp64 = with(Some(DataModel::Lp64));
        assert_eq!(lp64.matching_preset(), Some(Preset::Default));
        assert_ne!(lp64.settings_hash(), base.settings_hash());
        assert_eq!(lp64.to_json()["data_model"], "lp64");
        let config: SettingsConfig =
            toml::from_str("[environment]\ndata_model = \"llp64\"\n").unwrap();
        assert_eq!(
            AnalysisSettings::resolve(&config).unwrap().data_model,
            DataModel::Llp64
        );
        let mut set = SettingsConfig::default();
        set.set("data_model=lp64").unwrap();
        assert_eq!(
            AnalysisSettings::resolve(&set).unwrap().data_model,
            DataModel::Lp64
        );
        assert!(set.set("data_model=ilp64").is_err());
        assert!("ilp32".parse::<DataModel>().is_ok());
        assert!("ilp64".parse::<DataModel>().is_err());
    }
}
