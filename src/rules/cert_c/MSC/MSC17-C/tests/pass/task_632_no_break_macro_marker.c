/*
 * Rule: MSC17-C
 * Source: sqlite src/insert.c (task 632)
 * Status: PASS - Should NOT trigger MSC17-C violation
 *
 * sqlite's `deliberate_fall_through` marker macro expands to
 * `__attribute__((fallthrough));` (semicolon included in the macro body),
 * so it's invoked bare, with no trailing `;` in the source. With no
 * preprocessor, aurora-lint parses that as a bare `type_identifier` (tree-sitter's
 * error recovery for a statement position it doesn't recognize) rather
 * than an `expression_statement`. The adjacent `/* no break */` comment
 * uses different wording than "fall through" entirely.
 */

void f(int op) {
  switch (op) {
  case 1: {
    g();
    /* no break */ deliberate_fall_through
  }
  case 2:
    h();
    break;
  }
}
