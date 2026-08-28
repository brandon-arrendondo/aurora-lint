/*
 * Rule: MSC13-C
 * Source: raylib src/platforms/rcore_android.c (task 386 regression, task
 *         166/632-adjacent benchmark investigation, 2026-08-28)
 * Status: PASS - Should NOT trigger MSC13-C violation
 *
 * A `for (int i = 0; ...; i++) { ... i ... }` loop variable is declared as
 * a direct child of the for_statement itself, not of any compound_statement
 * -- find_enclosing_declaration_for_identifier previously only searched
 * compound_statement children, so it never resolved the declaration for any
 * occurrence of `i` (condition, update, or body), making every for-loop
 * variable in the codebase look "never read". Fixed alongside task 386's
 * shadow-aware MSC13-C/CON07-C rewrite exposing the gap.
 */

void useKey(int k);

void f(int maxKeys) {
  for (int i = 0; i < maxKeys; i++) {
    useKey(i);
  }
}
