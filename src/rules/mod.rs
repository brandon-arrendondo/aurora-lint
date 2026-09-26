//! The [`CertRule`] trait every rule implements, [`RuleViolation`] (the
//! result of running one), and [`RuleRegistry`] (the collection every
//! enabled rule is looked up through).

/// BISSELL-specific rules (`BRULE-###`) beyond the CERT C standard set.
pub mod brules;
mod cert_c;

use crate::analyze::cfg::FunctionCfg;
use crate::analyze::context::ProjectContext;
use crate::analyze::value_range::RangeAnalysisResult;
use std::collections::HashMap;
use tree_sitter::Node;

/// One CERT C rule or BISSELL-specific rule (`BRULE-###`) checker.
pub trait CertRule {
    /// This rule's identifier (e.g. `"ARR30-C"`).
    fn rule_id(&self) -> &'static str;
    /// Human-readable description of what this rule checks.
    fn description(&self) -> &'static str;
    /// This rule's default severity, absent a manifest override.
    fn severity(&self) -> crate::manifest::Severity;
    /// Whether this is a CERT rule or recommendation, derived from
    /// [`Self::rule_id`] by CERT's numbering; `None` when the id is not a
    /// CERT C id. Do not override this for a CERT C rule: the id is the
    /// only source of truth, and a test asserts no rule disagrees with it.
    fn category(&self) -> Option<crate::manifest::RuleCategory> {
        crate::manifest::RuleCategory::from_cert_id(self.rule_id())
    }
    /// This rule's default CERT identifier, absent a manifest override.
    fn cert_id(&self) -> &'static str;

    /// Default `check()` for rules using the standard mut-accumulator pattern:
    /// allocate an empty `Vec`, delegate to `scan()` to populate it, return it.
    /// Rules with a different shape (e.g. no violations vec, early returns)
    /// should override `check()` directly instead of implementing `scan()`.
    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.scan(node, source, &mut violations);
        violations
    }

    /// Populate `violations` by walking `node`. Only called by the default
    /// `check()` impl above; rules that override `check()` never call this.
    fn scan(&self, _node: &Node, _source: &str, _violations: &mut Vec<RuleViolation>) {
        unreachable!("scan() has no implementation; this rule should override check() instead")
    }

    /// Enhanced check that receives CFG data for flow-sensitive analysis.
    /// Default implementation delegates to `check()`, ignoring the CFG.
    /// Rules that benefit from CFG analysis can override this.
    fn check_with_cfg(
        &self,
        node: &Node,
        source: &str,
        _cfg: Option<&FunctionCfg>,
    ) -> Vec<RuleViolation> {
        self.check(node, source)
    }

    /// Inject cross-file context gathered by the pre-scan phase.
    /// Default is a no-op; only rules that need cross-file data override this.
    ///
    /// Called once per rule per scanned file. The context's tables are
    /// `Arc`-wrapped so that `context.<table>.clone()` is a handle, not a
    /// copy; keep the handle (`RefCell<Arc<..>>`) rather than deep-copying
    /// or merging tables here -- see the "Cross-file project context"
    /// section of `docs/design/internal-capability-catalog.md`.
    fn set_project_context(&self, _context: &ProjectContext) {}

    /// Inject per-file function CFGs for flow-sensitive analysis.
    /// Default is a no-op; only rules that need CFG data override this.
    fn set_function_cfgs(&self, _cfgs: &HashMap<usize, FunctionCfg>) {}

    /// Returns true if this rule applies to the given file path.
    /// Default: applies to all files. Override for rules that are
    /// specific to a file type (e.g. header-only rules like PRE06-C).
    fn applies_to_file(&self, _file_path: &str) -> bool {
        true
    }

    /// Inject pre-computed value-range analysis results for flow-sensitive
    /// integer range checking. Default is a no-op; only rules that need
    /// VRA data override this.
    fn set_vra_results(&self, _results: &HashMap<usize, RangeAnalysisResult>) {}

    /// Returns true if this rule uses value-range analysis.
    /// Used to avoid computing VRA when no enabled rules need it.
    fn needs_vra(&self) -> bool {
        false
    }
}

/// One instance of a rule firing at a specific location.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RuleViolation {
    /// Which rule produced this violation.
    pub rule_id: String,
    /// Severity of this violation.
    pub severity: crate::manifest::Severity,
    /// Human-readable description of what was found.
    pub message: String,
    /// Path to the file the violation was found in.
    pub file_path: String,
    /// 1-indexed line the violation is reported at.
    pub line: usize,
    /// 1-indexed column the violation is reported at.
    pub column: usize,
    /// Optional suggested fix, shown to the user alongside the message.
    pub suggestion: Option<String>,
    /// Indicates if this violation requires manual investigation by the user.
    /// Used for ambiguous cases where the tool cannot definitively determine if it's a violation.
    /// `None` or `Some(false)` means it's a definite violation.
    /// `Some(true)` means it requires manual review.
    #[doc(hidden)]
    pub requires_manual_review: Option<bool>,
}

impl Default for RuleViolation {
    fn default() -> Self {
        Self {
            rule_id: String::new(),
            severity: crate::manifest::Severity::Low,
            message: String::new(),
            file_path: String::new(),
            line: 0,
            column: 0,
            suggestion: None,
            requires_manual_review: None,
        }
    }
}

impl RuleViolation {
    /// Returns true if this violation requires manual review
    pub fn needs_manual_review(&self) -> bool {
        self.requires_manual_review.unwrap_or(false)
    }
}

/// The collection of every registered rule, looked up by ID.
pub struct RuleRegistry {
    rules: Vec<Box<dyn CertRule>>,
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// `rule_id`'s description from `registry`, or `"Unknown rule"` if unregistered.
pub fn get_rule_description(registry: &RuleRegistry, rule_id: &str) -> String {
    if let Some(rule) = registry.get_rule(rule_id) {
        rule.description().to_string()
    } else {
        "Unknown rule".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::RuleRegistry;
    use crate::manifest::{RuleCategory, NON_CERT_C_IDS};
    use std::path::Path;

    #[test]
    fn every_registered_rule_category_agrees_with_its_cert_id() {
        let registry = RuleRegistry::new();
        let disagreeing: Vec<_> = registry
            .all_rules()
            .iter()
            .filter(|rule| rule.category() != RuleCategory::from_cert_id(rule.rule_id()))
            .map(|rule| rule.rule_id())
            .collect();
        assert!(
            disagreeing.is_empty(),
            "category() disagrees with CERT numbering (00-29 recommendation, 30+ rule): \
             {disagreeing:?}"
        );
    }

    #[test]
    fn every_rule_toml_type_agrees_with_its_cert_id() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/rules/cert_c");
        let mut checked = 0;
        let mut disagreeing = Vec::new();
        for entry in walkdir::WalkDir::new(&root).min_depth(3).max_depth(3) {
            let path = entry.unwrap().into_path();
            if path.extension().is_none_or(|ext| ext != "toml") {
                continue;
            }
            let doc: toml::Table = std::fs::read_to_string(&path).unwrap().parse().unwrap();
            let metadata = doc["metadata"].as_table().unwrap();
            let id = metadata["id"].as_str().unwrap();
            let Some(expected) = RuleCategory::from_cert_id(id) else {
                assert!(
                    NON_CERT_C_IDS.contains(&id),
                    "{} has an id that is not a CERT C id: {id}",
                    path.display()
                );
                continue;
            };
            let expected = match expected {
                RuleCategory::Rule => "rule",
                RuleCategory::Recommendation => "recommendation",
            };
            checked += 1;
            if metadata.get("type").and_then(|t| t.as_str()) != Some(expected) {
                disagreeing.push(id.to_string());
            }
        }
        assert!(checked > 0, "found no rule TOMLs under {}", root.display());
        assert!(
            disagreeing.is_empty(),
            "[metadata] type disagrees with CERT numbering (00-29 recommendation, 30+ rule): \
             {disagreeing:?}"
        );
    }

    #[test]
    fn non_cert_c_ids_are_still_registered() {
        // Keeps the exception list from outliving the rules it excuses.
        let registry = RuleRegistry::new();
        for id in NON_CERT_C_IDS {
            assert!(
                registry.get_rule(id).is_some(),
                "{id} is no longer registered; remove it from NON_CERT_C_IDS"
            );
        }
    }
}
