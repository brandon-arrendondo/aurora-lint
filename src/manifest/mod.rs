use crate::settings::{EnvironmentConfig, PolicyConfig, Preset, SettingsConfig};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

pub mod removed;

use removed::RemovedRule;

/// The parsed rule manifest (TOML config): which rules run, at what
/// severity, and with what per-rule overrides.
///
/// Unknown top-level keys are refused: a misspelled `[enviroment]` table
/// must not silently leave the analysis on the default settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleManifest {
    /// Manifest-level identifying info (name, version, CERT edition).
    pub metadata: ManifestMetadata,
    /// The rule configs themselves, namespaced by rule family.
    pub rules: RuleNamespaces,
    /// `profile = "default" | "strict"`: the preset both axes start from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<Preset>,
    /// The `[policy]` table: overrides of the policy axis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyConfig>,
    /// The `[environment]` table: overrides of the environment axis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<EnvironmentConfig>,
    /// The `[scope]` table: path globs left out of the analysis, added to
    /// the command line's `--exclude-all`, `--report-exclude` and
    /// `--prescan-exclude`.
    #[serde(default, skip_serializing_if = "ScopeConfig::is_empty")]
    pub scope: ScopeConfig,
}

/// Which files a scan leaves out, as path globs relative to the scanned
/// root. `exclude_all` leaves a file out of everything; the other two are
/// the partial cases.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeConfig {
    /// Not scanned, not reported, and not read by the cross-file prescan:
    /// the file might as well not exist (test suites, example programs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_all: Vec<String>,
    /// No findings, but still read by the prescan, so its definitions keep
    /// feeding cross-file facts: vendored code the product links and ships.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub report_exclude: Vec<String>,
    /// Scanned and reported, but not read by the prescan, so its
    /// definitions do not stand for the functions and macros other files
    /// call: stubs, fuzz harnesses, alternate-platform files that do not
    /// link into the product under analysis.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prescan_exclude: Vec<String>,
}

impl ScopeConfig {
    /// No glob in any of the three lists.
    pub fn is_empty(&self) -> bool {
        self.exclude_all.is_empty()
            && self.report_exclude.is_empty()
            && self.prescan_exclude.is_empty()
    }
}

/// Rule configs grouped by family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleNamespaces {
    /// CERT C rules (`ARR30-C`, `STR31-C`, ...), keyed by rule ID.
    pub cert_c: HashMap<String, RuleConfig>,
    /// BISSELL-specific rules (`BRULE-###`), keyed by rule ID.
    #[serde(default)]
    pub brules: HashMap<String, RuleConfig>,
}

/// Identifying metadata for a manifest, independent of which rules it configures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestMetadata {
    /// Human-readable name for this rule set.
    pub name: String,
    /// Manifest version string.
    pub version: String,
    /// Optional free-text description of this rule set.
    pub description: Option<String>,
    /// CERT C edition this manifest targets (e.g. `"2016"`).
    pub cert_version: String,
}

/// Per-rule configuration; every field but `enabled` is optional and falls
/// back to the rule implementation's own default when unset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    /// Whether this rule runs at all.
    pub enabled: bool,
    /// Overrides the rule's default severity.
    pub severity: Option<Severity>,
    /// Overrides the rule's default description.
    pub description: Option<String>,
}

/// How serious a violation of a rule is.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    /// Minor — style/best-practice concern.
    Low,
    /// Worth fixing but not urgent.
    Medium,
    /// Likely to cause real defects.
    High,
    /// Security-relevant or likely to cause undefined behavior.
    Critical,
}

impl Severity {
    /// Numeric ordering for this severity, `Low` (0) to `Critical` (3).
    pub fn as_level(&self) -> u8 {
        match self {
            Severity::Low => 0,
            Severity::Medium => 1,
            Severity::High => 2,
            Severity::Critical => 3,
        }
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_level().cmp(&other.as_level())
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(format!(
                "Invalid severity: '{}'. Valid values: Low, Medium, High, Critical",
                s
            )),
        }
    }
}

/// Whether a CERT identifier names a mandatory rule or an advisory
/// recommendation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleCategory {
    /// A mandatory CERT rule.
    Rule,
    /// An advisory CERT recommendation.
    Recommendation,
}

/// Ids registered under `cert_c` that are not CERT C identifiers, so have no
/// rule/recommendation standing: `CON50-C`, `FIO50-C` and `FIO51-C` are CERT
/// C++ ids, and `MSC42-C`, `POS55-C` and `WIN05-C` are not numbers in the
/// CERT C standard at all.
pub const NON_CERT_C_IDS: &[&str] = &[
    "CON50-C", "FIO50-C", "FIO51-C", "MSC42-C", "POS55-C", "WIN05-C",
];

impl RuleCategory {
    /// The category CERT C's own numbering assigns `id`: within each
    /// three-letter category, 00-29 are recommendations and 30 and above are
    /// rules. This is the single source of truth for the split; a rule's
    /// [`crate::rules::CertRule::category`] and its TOML `[metadata] type` are
    /// both checked against it. `None` for anything that is not a CERT C id,
    /// including [`NON_CERT_C_IDS`].
    pub fn from_cert_id(id: &str) -> Option<Self> {
        if NON_CERT_C_IDS.contains(&id) {
            return None;
        }
        let number = id.strip_suffix("-C")?;
        let (prefix, digits) = number.split_at_checked(3)?;
        if !prefix.bytes().all(|b| b.is_ascii_uppercase())
            || digits.len() != 2
            || !digits.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let n: u32 = digits.parse().ok()?;
        Some(if n >= 30 {
            RuleCategory::Rule
        } else {
            RuleCategory::Recommendation
        })
    }
}

/// Per-rule manifest keys aurora-lint used to accept and no longer does,
/// each with why it went. A manifest that still sets one loads, with a
/// warning, rather than failing on a key that never changed any output.
pub const REMOVED_RULE_KEYS: &[(&str, &str)] = &[
    (
        "category",
        "it never had any effect; whether a rule is a CERT rule or a \
         recommendation comes from its CERT id",
    ),
    (
        "cert_id",
        "it never had any effect; a rule's CERT id is its rule id",
    ),
    (
        "parameters",
        "it never had any effect; no rule takes parameters from the manifest",
    ),
];

/// One warning per rule that sets a key in [`REMOVED_RULE_KEYS`], in rule
/// order. Empty when `content` is not valid TOML: the real parse reports
/// that.
fn removed_rule_key_warnings(content: &str) -> Vec<String> {
    let Ok(doc) = content.parse::<toml::Table>() else {
        return Vec::new();
    };
    let Some(namespaces) = doc.get("rules").and_then(|r| r.as_table()) else {
        return Vec::new();
    };
    let mut warnings = Vec::new();
    for rules in namespaces.values().filter_map(|n| n.as_table()) {
        for (rule_id, config) in rules {
            let Some(config) = config.as_table() else {
                continue;
            };
            for (key, why) in REMOVED_RULE_KEYS {
                if config.contains_key(*key) {
                    warnings.push(format!(
                        "ignoring `{key}` for rule {rule_id}: the per-rule `{key}` \
                         manifest key has been removed ({why})"
                    ));
                }
            }
        }
    }
    warnings
}

/// One warning per removed rule (see [`removed`]) that `content` still has
/// a `[rules.<namespace>.<id>]` block for, in `removed` order. Empty when
/// `content` is not valid TOML: the real parse reports that.
fn removed_rule_warnings(content: &str, removed: &[RemovedRule]) -> Vec<String> {
    let Ok(doc) = content.parse::<toml::Table>() else {
        return Vec::new();
    };
    let Some(namespaces) = doc.get("rules").and_then(|r| r.as_table()) else {
        return Vec::new();
    };
    removed
        .iter()
        .filter(|rule| {
            namespaces
                .values()
                .filter_map(|n| n.as_table())
                .any(|rules| rules.contains_key(&rule.id))
        })
        .map(RemovedRule::warning)
        .collect()
}

impl RuleManifest {
    /// Read and parse `path` as a TOML rule manifest.
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read manifest file: {}", path))?;

        Self::from_toml_str(&content)
            .with_context(|| format!("Failed to parse manifest file: {}", path))
    }

    /// Parse `content` as a TOML rule manifest, warning on stderr about any
    /// per-rule key in [`REMOVED_RULE_KEYS`] and any block for a removed rule
    /// (both ignored, never an error).
    pub fn from_toml_str(content: &str) -> Result<Self> {
        Self::from_toml_str_with(content, removed::removed_rules())
    }

    /// [`from_toml_str`](Self::from_toml_str) against an explicit
    /// removed-rules table.
    fn from_toml_str_with(content: &str, removed: &[RemovedRule]) -> Result<Self> {
        for warning in removed_rule_key_warnings(content) {
            eprintln!("Warning: {warning}");
        }
        for warning in removed_rule_warnings(content, removed) {
            removed::warn_once(&warning);
        }
        let mut manifest: RuleManifest = toml::from_str(content)?;
        manifest.drop_removed(removed);
        Ok(manifest)
    }

    /// Forget every block for a rule in `removed`, so a removed rule is
    /// neither run nor reported as unimplemented.
    fn drop_removed(&mut self, removed: &[RemovedRule]) {
        for rule in removed {
            self.rules.cert_c.remove(&rule.id);
            self.rules.brules.remove(&rule.id);
        }
    }

    /// The policy and environment settings this manifest declares, before
    /// any command-line override.
    pub fn settings_config(&self) -> SettingsConfig {
        SettingsConfig {
            profile: self.profile,
            policy: self.policy.clone(),
            environment: self.environment.clone(),
        }
    }

    /// A complete, commented configuration file (`--write-config`): the
    /// settings `current` resolves to (see
    /// [`render_config_settings`](crate::settings::render_config_settings)),
    /// this manifest's `[scope]` and metadata, and each of its rules. It
    /// loads back as a manifest, and resolves to the same settings.
    pub fn render_config(&self, current: &crate::settings::AnalysisSettings) -> String {
        let mut out = String::from(
            "# aurora-lint configuration, generated by --write-config.\n\
             #\n\
             # A key at its built-in default is commented out; uncomment and edit one to override\n\
             # it. Precedence, highest first: the command line, this file, the data model's bundle,\n\
             # the ISO minimum. Check an edited file without scanning:\n\
             #   aurora-lint --check-config --manifest THIS_FILE\n\n",
        );
        out.push_str(&crate::settings::render_config_settings(current));

        out.push_str(
            "\n# Path globs, relative to the scanned root, left out of the analysis.\n[scope]\n",
        );
        let globs = |out: &mut String, key: &str, note: &str, values: &[String]| {
            out.push_str(&format!("# {note}\n"));
            if values.is_empty() {
                out.push_str(&format!("# {key} = [\"tests/**\"]\n"));
            } else {
                out.push_str(&format!("{key} = {}\n", toml::Value::from(values.to_vec())));
            }
        };
        globs(
            &mut out,
            "exclude_all",
            "Not scanned, not reported, not read by the cross-file prescan.",
            &self.scope.exclude_all,
        );
        globs(
            &mut out,
            "report_exclude",
            "No findings, but still read by the prescan (vendored code the product ships).",
            &self.scope.report_exclude,
        );
        globs(
            &mut out,
            "prescan_exclude",
            "Scanned and reported, but not read by the prescan (stubs, fuzz harnesses).",
            &self.scope.prescan_exclude,
        );

        out.push_str("\n[metadata]\n");
        out.push_str(&format!("name = {:?}\n", self.metadata.name));
        out.push_str(&format!("version = {:?}\n", self.metadata.version));
        if let Some(description) = &self.metadata.description {
            out.push_str(&format!("description = {description:?}\n"));
        }
        out.push_str(&format!(
            "cert_version = {:?}\n",
            self.metadata.cert_version
        ));

        for (family, rules) in [
            ("cert_c", &self.rules.cert_c),
            ("brules", &self.rules.brules),
        ] {
            let mut ids: Vec<&String> = rules.keys().collect();
            ids.sort();
            for id in ids {
                let config = &rules[id];
                out.push_str(&format!("\n[rules.{family}.{id}]\n"));
                out.push_str(&format!("enabled = {}\n", config.enabled));
                if let Some(severity) = &config.severity {
                    if let Ok(serde_json::Value::String(name)) = serde_json::to_value(severity) {
                        out.push_str(&format!("severity = {name:?}\n"));
                    }
                }
                if let Some(description) = &config.description {
                    out.push_str(&format!("description = {description:?}\n"));
                }
            }
        }
        out
    }

    /// Every rule ID/config pair across both namespaces with `enabled = true`.
    pub fn enabled_rules(&self) -> impl Iterator<Item = (&String, &RuleConfig)> {
        self.rules
            .cert_c
            .iter()
            .chain(self.rules.brules.iter())
            .filter(|(_, config)| config.enabled)
    }

    /// The config for `rule_id`, checked against both namespaces.
    pub fn get_rule(&self, rule_id: &str) -> Option<&RuleConfig> {
        self.rules
            .cert_c
            .get(rule_id)
            .or_else(|| self.rules.brules.get(rule_id))
    }

    /// Mutable access to the config for `rule_id`, checked against both namespaces.
    pub fn get_rule_mut(&mut self, rule_id: &str) -> Option<&mut RuleConfig> {
        if self.rules.cert_c.contains_key(rule_id) {
            self.rules.cert_c.get_mut(rule_id)
        } else {
            self.rules.brules.get_mut(rule_id)
        }
    }

    /// Disables every rule not named in `rule_ids` (e.g. from `--rules`),
    /// so callers that only want a subset (single-rule debugging, targeted
    /// re-scans) skip the disabled rules' work entirely -- including
    /// expensive shared setup like VRA, which is only computed when at
    /// least one *enabled* rule needs it. Intersects with the manifest
    /// rather than overriding it: a rule the manifest already has disabled
    /// stays disabled even if named in `rule_ids`, matching the pre-existing
    /// `--rules` semantics (it never ran, so it never appeared in the
    /// post-analysis filter's output either).
    pub fn restrict_to(&mut self, rule_ids: &std::collections::HashSet<String>) {
        for (id, config) in self.rules.cert_c.iter_mut() {
            config.enabled = config.enabled && rule_ids.contains(id);
        }
        for (id, config) in self.rules.brules.iter_mut() {
            config.enabled = config.enabled && rule_ids.contains(id);
        }
    }
}

impl Default for RuleManifest {
    fn default() -> Self {
        let mut cert_c_rules = HashMap::new();

        // Example CERT C rules - only enabled flag is set, other fields come from rule implementation
        cert_c_rules.insert(
            "ARR30-C".to_string(),
            RuleConfig {
                enabled: true,
                severity: None,    // Use rule's default severity
                description: None, // Use rule's default description
            },
        );

        cert_c_rules.insert(
            "STR31-C".to_string(),
            RuleConfig {
                enabled: true,
                severity: None,    // Use rule's default severity
                description: None, // Use rule's default description
            },
        );

        Self {
            metadata: ManifestMetadata {
                name: "Default CERT C Rules".to_string(),
                version: "1.0.0".to_string(),
                description: Some("Default set of CERT C rules and recommendations".to_string()),
                cert_version: "2016".to_string(),
            },
            rules: RuleNamespaces {
                cert_c: cert_c_rules,
                brules: HashMap::new(),
            },
            profile: None,
            policy: None,
            environment: None,
            scope: ScopeConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::removed::{parse_removed_rules, removed_rules, Disposition, RemovedRule};
    use super::{removed_rule_key_warnings, removed_rule_warnings, RuleCategory, RuleManifest};

    const WITH_REMOVED_KEYS: &str = r#"
[metadata]
name = "t"
version = "1"
cert_version = "2016"

[rules.cert_c.ARR30-C]
enabled = true
category = "Rule"

[rules.cert_c.STR31-C]
enabled = false

[rules.cert_c.MEM30-C]
enabled = true
cert_id = "MEM30-C"

[rules.cert_c.MEM30-C.parameters]
threshold = "4"

[rules.brules.BRULE-065]
enabled = true
category = "Recommendation"
"#;

    #[test]
    fn removed_keys_still_load() {
        // Fails if RuleConfig starts refusing unknown keys: a removed key
        // must warn, never stop a manifest from loading.
        let manifest = RuleManifest::from_toml_str(WITH_REMOVED_KEYS).unwrap();
        assert!(manifest.get_rule("ARR30-C").unwrap().enabled);
        assert!(!manifest.get_rule("STR31-C").unwrap().enabled);
        assert!(manifest.get_rule("BRULE-065").unwrap().enabled);
        assert!(manifest.get_rule("MEM30-C").unwrap().enabled);
    }

    #[test]
    fn removed_keys_warn_once_per_rule_and_key() {
        let mut warnings = removed_rule_key_warnings(WITH_REMOVED_KEYS);
        warnings.sort();
        let heads: Vec<_> = warnings
            .iter()
            .map(|w| w.split(':').next().unwrap())
            .collect();
        assert_eq!(
            heads,
            [
                "ignoring `category` for rule ARR30-C",
                "ignoring `category` for rule BRULE-065",
                "ignoring `cert_id` for rule MEM30-C",
                "ignoring `parameters` for rule MEM30-C",
            ]
        );
    }

    #[test]
    fn manifest_without_removed_keys_warns_about_nothing() {
        let default_manifest = include_str!("../../rules_templates/rules-all.toml");
        assert!(removed_rule_key_warnings(default_manifest).is_empty());
    }

    #[test]
    fn from_cert_id_splits_at_30() {
        assert_eq!(
            RuleCategory::from_cert_id("PRE00-C"),
            Some(RuleCategory::Recommendation)
        );
        assert_eq!(
            RuleCategory::from_cert_id("ARR29-C"),
            Some(RuleCategory::Recommendation)
        );
        assert_eq!(
            RuleCategory::from_cert_id("PRE30-C"),
            Some(RuleCategory::Rule)
        );
        assert_eq!(
            RuleCategory::from_cert_id("POS54-C"),
            Some(RuleCategory::Rule)
        );
    }

    #[test]
    fn from_cert_id_rejects_non_cert_ids() {
        for id in [
            "FIO50-C",
            "WIN05-C",
            "BRULE-065",
            "ARR30",
            "ARR3-C",
            "arr30-C",
            "ARR30-CPP",
        ] {
            assert_eq!(RuleCategory::from_cert_id(id), None, "{id}");
        }
    }

    /// A removed-rules table for the tests only: no real rule is removed.
    fn test_removed() -> Vec<RemovedRule> {
        parse_removed_rules(
            r#"
[[removed]]
id = "STR31-C"
removed_in = "9.9.9"
disposition = "covered"
reason = "Test-only entry."
covered_by = ["ARR30-C"]
"#,
        )
        .unwrap()
    }

    #[test]
    fn a_removed_rule_still_loads_and_is_dropped() {
        let manifest =
            RuleManifest::from_toml_str_with(WITH_REMOVED_KEYS, &test_removed()).unwrap();
        assert!(manifest.get_rule("STR31-C").is_none());
        assert!(manifest.get_rule("ARR30-C").unwrap().enabled);
    }

    #[test]
    fn a_removed_rule_warns_once_with_its_reason() {
        let warnings = removed_rule_warnings(WITH_REMOVED_KEYS, &test_removed());
        assert_eq!(
            warnings,
            [
                "STR31-C was removed in v9.9.9 (covered by another rule): Test-only entry; \
              covered by ARR30-C. Its configuration block is ignored."
            ]
        );
    }

    #[test]
    fn a_manifest_without_removed_rules_warns_about_nothing() {
        let default_manifest = include_str!("../../rules_templates/rules-all.toml");
        assert!(removed_rule_warnings(default_manifest, removed_rules()).is_empty());
    }

    #[test]
    fn the_shipped_removed_rules_table_parses() {
        // removed_rules() panics on an invalid table; this makes CI say so.
        let _ = removed_rules();
    }

    #[test]
    fn no_removed_rule_is_still_in_the_default_manifest() {
        let default_manifest: toml::Table = include_str!("../../rules_templates/rules-all.toml")
            .parse()
            .unwrap();
        let rules = default_manifest["rules"].as_table().unwrap();
        for rule in removed_rules() {
            assert!(
                rules
                    .values()
                    .filter_map(|n| n.as_table())
                    .all(|ns| !ns.contains_key(&rule.id)),
                "{} is removed but still has a block in rules-all.toml",
                rule.id
            );
        }
    }

    #[test]
    fn a_covered_removal_must_name_its_covering_rule() {
        let err = parse_removed_rules(
            r#"
[[removed]]
id = "ERR00-C"
removed_in = "1.0.0"
disposition = "covered"
reason = "x"
"#,
        )
        .unwrap_err();
        assert!(err.contains("names no covering rule"), "{err}");
    }

    #[test]
    fn a_deprecated_removal_names_its_successor_as_replaced_by() {
        let rule = RemovedRule {
            id: "FIO04-C".into(),
            removed_in: "1.0.0".into(),
            disposition: Disposition::Deprecated,
            reason: "CERT merged it.".into(),
            covered_by: vec!["ERR33-C".into()],
        };
        assert!(rule.warning().contains("; replaced by ERR33-C."));
    }

    #[test]
    fn a_duplicate_or_v_prefixed_entry_is_refused() {
        let entry = |v: &str| {
            format!(
                "[[removed]]\nid = \"ERR00-C\"\nremoved_in = \"{v}\"\n\
                 disposition = \"unenforceable\"\nreason = \"x\"\n"
            )
        };
        assert!(parse_removed_rules(&entry("v1.0.0")).is_err());
        assert!(parse_removed_rules(&format!("{}{}", entry("1.0.0"), entry("1.0.0"))).is_err());
    }
}
