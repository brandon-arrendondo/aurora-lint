// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! MSC24-C: Do not use deprecated or obsolescent functions
//!
//! `gets()` was deprecated by C99 TC3 and removed entirely from C11. A
//! further set of Annex K-superseded functions -- string/memory copy
//! functions and numeric-parsing functions with no error detection -- are
//! obsolescent: a bounds-checked or error-detecting replacement exists and
//! should be preferred. This rule flags calls to any function on that list.
//!
//! Note: this deliberately excludes several functions the wiki also lists
//! as obsolescent: `fopen`/`freopen` (superseded by `fopen_s`/`freopen_s`
//! for exclusive file access) and `atof`/`atoi`/`atol`/`atoll` (superseded
//! by the `strto*` family for error detection) are all extremely common,
//! legitimate, portable C with no realistic drop-in `_s`/`strto*`
//! replacement in most non-Annex-K codebases; flagging every call would be
//! a large real-world FP source for comparatively low security value
//! (silent parse failure, not memory corruption). `strcpy`/`strcat`/
//! `sprintf` are still flagged per the wiki's own example, in addition to
//! (not instead of) STR31-C/STR30-C's buffer-safety-aware analysis of the
//! same calls -- MSC24-C's concern (deprecated API) is orthogonal to
//! theirs (provable buffer safety).
//!
//! `sscanf` was removed from this list (task 629): it is not on CERT's
//! actual MSC24-C obsolescent-function table, and its suggested
//! replacement (`sscanf_s()`) is an optional, rarely-implemented Annex K
//! extension unavailable on glibc -- flagging it was a 100% FP class (47
//! of hostap's ctrl_iface.c findings alone, per task 625's ground_truth).
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/MSC24-C.+Do+not+use+deprecated+or+obsolescent+functions

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use tree_sitter::Node;

const OBSOLESCENT_FUNCS: &[(&str, &str)] = &[
    ("gets", "gets_s() (or fgets())"),
    ("strcpy", "strcpy_s()"),
    ("strcat", "strcat_s()"),
    ("sprintf", "sprintf_s() (or snprintf())"),
    ("vsprintf", "vsprintf_s() (or vsnprintf())"),
    ("scanf", "scanf_s()"),
    ("fscanf", "fscanf_s()"),
    ("strtok", "strtok_s()"),
    ("asctime", "asctime_s()"),
    ("ctime", "ctime_s()"),
    ("rewind", "fseek()"),
    ("setbuf", "setvbuf()"),
];

#[derive(Debug)]
pub struct Msc24C;

impl Msc24C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Msc24C
    }

    fn traverse(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call in query::find_descendants_of_kind(*root, "call_expression") {
            let Some(func) = call.child_by_field_name("function") else {
                continue;
            };
            if func.kind() != "identifier" {
                continue;
            }
            let func_name = ast_utils::get_node_text(&func, source);
            let Some((_, replacement)) = OBSOLESCENT_FUNCS
                .iter()
                .find(|(name, _)| *name == func_name)
            else {
                continue;
            };

            let pos = call.start_position();
            violations.push(RuleViolation {
                rule_id: "MSC24-C".to_string(),
                severity: Severity::Medium,
                line: pos.row + 1,
                column: pos.column + 1,
                message: format!(
                    "'{}' is deprecated/obsolescent -- prefer {}",
                    func_name, replacement
                ),
                file_path: String::new(),
                suggestion: Some(format!("Replace '{}' with {}", func_name, replacement)),
                requires_manual_review: Some(false),
            });
        }
    }
}

impl CertRule for Msc24C {
    fn rule_id(&self) -> &'static str {
        "MSC24-C"
    }

    fn description(&self) -> &'static str {
        "Do not use deprecated or obsolescent functions"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "MSC24-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }
}
