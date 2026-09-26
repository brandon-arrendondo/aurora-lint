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

use anyhow::{bail, Result};
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
        summary: "A function declared _Noreturn is trusted not to return; otherwise only a \
                  body verified never to return proves it.",
        basis: "C11 6.7.4p8. A GNU noreturn attribute is proof under neither policy.",
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
    /// Per-contract overrides.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub overrides: BTreeMap<String, bool>,
}

impl SettingsConfig {
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
            mine.overrides
                .extend(e.overrides.iter().map(|(k, v)| (k.clone(), *v)));
        }
    }

    /// Record a `NAME=VALUE` override, routed to the axis `NAME` belongs to.
    pub fn set(&mut self, assignment: &str) -> Result<()> {
        let Some((name, value)) = assignment.split_once('=') else {
            bail!("expected NAME=VALUE, got '{assignment}'");
        };
        let (name, value) = (name.trim(), value.trim());
        let value: bool = match value {
            "true" => true,
            "false" => false,
            _ => bail!("option '{name}' takes true or false, got '{value}'"),
        };
        let Some(spec) = option(name) else {
            bail!(
                "unknown option '{name}'; run --list-options for the supported set ({})",
                OPTIONS
                    .iter()
                    .map(|o| o.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
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
        if let Some(p) = &config.policy {
            policy = p.level.unwrap_or(policy);
        }
        if let Some(e) = &config.environment {
            environment = e.kind.unwrap_or(environment);
            libc = e.libc;
        }
        // A hosted implementation provides the standard library, so its
        // contracts hold unless a model says otherwise; a freestanding one
        // provides none unless a library is declared.
        if libc.is_none() && environment == EnvironmentKind::Hosted {
            libc = Some(Libc::IsoPosix);
        }

        let mut values = BTreeMap::new();
        for o in OPTIONS {
            let v = match o.source {
                Source::Policy { default, strict } => match policy {
                    Policy::Default => default,
                    Policy::Strict => strict,
                },
                Source::Hosted => environment == EnvironmentKind::Hosted,
                Source::Library(libcs) => libc.is_some_and(|l| libcs.contains(&l)),
                Source::Language => true,
            };
            values.insert(o.name, v);
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

        Ok(Self {
            policy,
            environment,
            libc,
            values,
        })
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

    /// The preset these settings equal exactly, if any.
    pub fn matching_preset(&self) -> Option<Preset> {
        [Preset::Default, Preset::Strict]
            .into_iter()
            .find(|p| *self == Self::preset(*p))
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
    /// knows is part of it, so adding an option changes every hash.
    pub fn settings_hash(&self) -> String {
        crate::utility::hash::sha256_hex(self.canonical_json().as_bytes())
    }

    fn identity_json(&self) -> serde_json::Value {
        let options: serde_json::Map<String, serde_json::Value> = self
            .values()
            .map(|(k, v)| (k.to_string(), serde_json::Value::Bool(v)))
            .collect();
        serde_json::json!({
            "preset": self.matching_preset(),
            "policy": self.policy,
            "environment": self.environment,
            "libc": self.libc,
            "options": options,
        })
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

display_via_serde!(Preset, Policy, EnvironmentKind, Libc);

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

/// The option listing as plain text, with each preset's value and the
/// value `current` resolves to.
pub fn render_text(current: &AnalysisSettings) -> String {
    let default = AnalysisSettings::preset(Preset::Default);
    let strict = AnalysisSettings::preset(Preset::Strict);
    let mut out = format!(
        "Current: policy={}, environment={}, libc={}\n\n",
        current.policy,
        current.environment,
        current
            .libc
            .map_or_else(|| "none".to_string(), |l| l.to_string()),
    );
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
    serde_json::json!({ "current": current.to_json(), "options": options })
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
    out
}
