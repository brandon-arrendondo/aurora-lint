use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleManifest {
    pub metadata: ManifestMetadata,
    pub rules: RuleNamespaces,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleNamespaces {
    pub cert_c: HashMap<String, RuleConfig>,
    #[serde(default)]
    pub brules: HashMap<String, RuleConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestMetadata {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub cert_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    pub enabled: bool,
    pub severity: Option<Severity>, // Optional: falls back to rule's default severity if not specified
    pub description: Option<String>, // Optional: falls back to rule's default description if not specified
    pub category: Option<RuleCategory>, // Optional: falls back to rule's default category if not specified
    pub cert_id: Option<String>, // Optional: falls back to rule's default cert_id if not specified
    pub parameters: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCategory {
    Rule,
    Recommendation,
}

impl RuleManifest {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read manifest file: {}", path))?;

        Self::from_toml_str(&content)
            .with_context(|| format!("Failed to parse manifest file: {}", path))
    }

    pub fn from_toml_str(content: &str) -> Result<Self> {
        let manifest: RuleManifest = toml::from_str(content)?;
        Ok(manifest)
    }

    pub fn enabled_rules(&self) -> impl Iterator<Item = (&String, &RuleConfig)> {
        self.rules
            .cert_c
            .iter()
            .chain(self.rules.brules.iter())
            .filter(|(_, config)| config.enabled)
    }

    pub fn get_rule(&self, rule_id: &str) -> Option<&RuleConfig> {
        self.rules
            .cert_c
            .get(rule_id)
            .or_else(|| self.rules.brules.get(rule_id))
    }

    pub fn get_rule_mut(&mut self, rule_id: &str) -> Option<&mut RuleConfig> {
        if self.rules.cert_c.contains_key(rule_id) {
            self.rules.cert_c.get_mut(rule_id)
        } else {
            self.rules.brules.get_mut(rule_id)
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
