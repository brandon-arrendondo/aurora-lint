/*
 * Rule: MSC13-C
 * Source: task 386 regression fix companion (2026-08-28)
 * Status: FAIL - Should trigger MSC13-C violation
 *
 * Companion to for_loop_var_read_in_body.c (pass): the fix that makes
 * find_enclosing_declaration_for_identifier resolve a for-loop variable's
 * own declaration must not over-correct into never flagging any for-loop
 * variable at all. A for-loop variable that is genuinely never read (not
 * even in the condition or update) is still a real violation.
 */

void f(void) {
  for (int i = 0;;) {
    break;
  }
}
