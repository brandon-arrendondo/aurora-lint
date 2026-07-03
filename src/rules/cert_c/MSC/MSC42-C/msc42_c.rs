//! MSC42-C: Do not use deprecated or weak cryptographic algorithms
//!
//! Flags use of weak/deprecated crypto algorithms in Windows Crypto API and
//! common crypto libraries. Detects weak algorithm constants passed to key
//! derivation and encryption functions.

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

/// Weak/deprecated algorithm constants (Windows Crypto API and generic).
const WEAK_ALGORITHMS: &[&str] = &[
    // Windows CALG_* constants
    "CALG_DES",
    "CALG_3DES",
    "CALG_3DES_112",
    "CALG_RC2",
    "CALG_RC4",
    "CALG_RC5",
    // OpenSSL EVP functions (detected as function calls separately)
    // Generic identifiers
    "ALG_DES",
    "ALG_3DES",
    "ALG_RC4",
    "ALG_RC5",
];

/// Crypto functions whose algorithm parameter should be checked.
/// (function_name, argument_index of algorithm param, 0-based)
const CRYPTO_FUNCTIONS: &[(&str, usize)] = &[
    ("CryptDeriveKey", 1),
    ("CryptGenKey", 1),
    ("CryptImportKey", 3),
];

/// Weak OpenSSL/generic cipher function names.
const WEAK_CIPHER_FUNCTIONS: &[&str] = &[
    "EVP_des_ecb",
    "EVP_des_cbc",
    "EVP_des_cfb",
    "EVP_des_ofb",
    "EVP_des_ede",
    "EVP_des_ede3",
    "EVP_des_ede_cbc",
    "EVP_des_ede3_cbc",
    "EVP_rc4",
    "EVP_rc2_cbc",
    "EVP_rc2_ecb",
    "EVP_rc2_cfb",
    "EVP_rc2_ofb",
    "EVP_rc5_32_12_16_cbc",
    "DES_set_key",
    "DES_ecb_encrypt",
    "DES_ncbc_encrypt",
    "DES_cbc_encrypt",
];

pub struct Msc42C;

impl Msc42C {
    pub fn new() -> Self {
        Self
    }

    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_crypto_call(&call, source, violations);
        }
    }

    fn check_crypto_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let func_name = match node.child_by_field_name("function") {
            Some(f) => get_node_text(&f, source).to_string(),
            None => return,
        };

        // Check for weak OpenSSL/generic cipher functions
        if WEAK_CIPHER_FUNCTIONS.contains(&func_name.as_str()) {
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                message: format!(
                    "Use of weak cryptographic function '{}'. \
                     Use a modern algorithm such as AES instead.",
                    func_name
                ),
                file_path: String::new(),
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                suggestion: Some(
                    "Replace with a strong algorithm (e.g., EVP_aes_256_cbc, AES-256)".to_string(),
                ),
                ..Default::default()
            });
            return;
        }

        // Check Windows Crypto API functions for weak algorithm constants
        for &(crypto_func, alg_arg_idx) in CRYPTO_FUNCTIONS {
            if func_name == crypto_func {
                if let Some(args) = node.child_by_field_name("arguments") {
                    if let Some(alg_arg) = self.get_nth_argument(&args, alg_arg_idx) {
                        let alg_text = get_node_text(&alg_arg, source).trim().to_string();
                        if WEAK_ALGORITHMS.contains(&alg_text.as_str()) {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: self.severity(),
                                message: format!(
                                    "Use of weak cryptographic algorithm '{}' in '{}'. \
                                     DES, 3DES, RC2, RC4, and RC5 are deprecated.",
                                    alg_text, func_name
                                ),
                                file_path: String::new(),
                                line: alg_arg.start_position().row + 1,
                                column: alg_arg.start_position().column + 1,
                                suggestion: Some(
                                    "Use CALG_AES_256 or CALG_AES_128 instead".to_string(),
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
                return;
            }
        }
    }

    /// Get the nth argument (0-based) from an argument_list node,
    /// skipping parentheses and commas.
    fn get_nth_argument<'a>(&self, args: &Node<'a>, index: usize) -> Option<Node<'a>> {
        let mut count = 0;
        for i in 0..args.child_count() {
            if let Some(child) = args.child(i) {
                let kind = child.kind();
                if kind != "(" && kind != ")" && kind != "," {
                    if count == index {
                        return Some(child);
                    }
                    count += 1;
                }
            }
        }
        None
    }
}

impl CertRule for Msc42C {
    fn rule_id(&self) -> &'static str {
        "MSC42-C"
    }

    fn description(&self) -> &'static str {
        "Do not use deprecated or weak cryptographic algorithms"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "MSC42-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}
