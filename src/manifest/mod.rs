use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

/// The parsed rule manifest (TOML config): which rules run, at what
/// severity, and with what per-rule overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleManifest {
    /// Manifest-level identifying info (name, version, CERT edition).
    pub metadata: ManifestMetadata,
    /// The rule configs themselves, namespaced by rule family.
    pub rules: RuleNamespaces,
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
    /// Overrides the rule's default category (rule vs. recommendation).
    pub category: Option<RuleCategory>,
    /// Overrides the rule's default CERT identifier.
    pub cert_id: Option<String>,
    /// Rule-specific parameters, passed through as raw strings.
    pub parameters: Option<HashMap<String, String>>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCategory {
    /// A mandatory CERT rule.
    Rule,
    /// An advisory CERT recommendation.
    Recommendation,
}

impl RuleManifest {
    /// Read and parse `path` as a TOML rule manifest.
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read manifest file: {}", path))?;

        Self::from_toml_str(&content)
            .with_context(|| format!("Failed to parse manifest file: {}", path))
    }

    /// Parse `content` as a TOML rule manifest.
    pub fn from_toml_str(content: &str) -> Result<Self> {
        let manifest: RuleManifest = toml::from_str(content)?;
        Ok(manifest)
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
                category: None,    // Use rule's default category
                cert_id: None,     // Use rule's default cert_id
                parameters: None,
            },
        );

        cert_c_rules.insert(
            "STR31-C".to_string(),
            RuleConfig {
                enabled: true,
                severity: None,    // Use rule's default severity
                description: None, // Use rule's default description
                category: None,    // Use rule's default category
                cert_id: None,     // Use rule's default cert_id
                parameters: None,
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
        }
    }
}
