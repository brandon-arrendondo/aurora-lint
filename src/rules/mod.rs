pub mod brules;
mod cert_c;

use crate::analyze::cfg::FunctionCfg;
use crate::analyze::context::ProjectContext;
use crate::analyze::value_range::RangeAnalysisResult;
use std::collections::HashMap;
use tree_sitter::Node;

pub trait CertRule {
    fn rule_id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn severity(&self) -> crate::manifest::Severity;
    fn category(&self) -> crate::manifest::RuleCategory;
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

#[derive(Debug, Clone, serde::Serialize)]
pub struct RuleViolation {
    pub rule_id: String,
    pub severity: crate::manifest::Severity,
    pub message: String,
    pub file_path: String,
    pub line: usize,
    pub column: usize,
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

pub struct RuleRegistry {
    rules: Vec<Box<dyn CertRule>>,
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub fn get_rule_description(registry: &RuleRegistry, rule_id: &str) -> String {
    if let Some(rule) = registry.get_rule(rule_id) {
        rule.description().to_string()
    } else {
        "Unknown rule".to_string()
    }
}
