Contributing
============

Adding a New CERT C Rule
------------------------

1. Create the rule directory and implementation file:

   ::

       src/rules/cert_c/CATEGORY/RULE-ID/rule_id_c.rs

2. Implement the ``CertRule`` trait:

   .. code-block:: rust

       use crate::prelude::*;

       pub struct Mem30C;

       impl CertRule for Mem30C {
           fn rule_id(&self) -> &'static str {
               "MEM30-C"
           }

           fn description(&self) -> &'static str {
               "Do not access freed memory"
           }

           fn check(
               &self,
               node: &Node,
               source: &str,
               _context: &ProjectContext,
           ) -> Vec<RuleViolation> {
               // Implementation here
               Vec::new()
           }
       }

3. Register the rule in ``src/rules/cert_c/mod.rs``.

4. Add test cases as ``.c`` files in ``src/rules/cert_c/CATEGORY/RULE-ID/tests/fail/``
   and ``tests/pass/``.

5. Add the rule entry to ``rules_templates/rules-all.toml``.

6. Build and test:

   ::

       cargo build
       cargo test --package sqc --lib -- rules::cert_c::RULE_ID::tests
       cargo fmt

Build Requirements
------------------

- **Rust**: 2021 edition (stable toolchain)
- **Platform**: Linux, macOS, Windows (cross-platform via crossterm)
- **Dependencies**: See ``Cargo.toml`` for the full list

::

    cargo build             # Debug build
    cargo build --release   # Release build (optimized)
    cargo test              # Run all tests
    cargo fmt               # Format code
