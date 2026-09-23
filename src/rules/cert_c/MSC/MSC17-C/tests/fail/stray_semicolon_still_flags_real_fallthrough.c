/*
 * Rule: MSC17-C
 * Source: task 634 companion (2026-08-28)
 * Status: FAIL - Should trigger MSC17-C violation
 *
 * Companion to task_634_stray_semicolon_after_braced_break.c (pass): a
 * stray trailing `;` after a braced case body must only be skipped when
 * looking for the *real* last item -- if that real item genuinely doesn't
 * terminate, the violation must still fire.
 */

void f(int op) {
  switch (op) {
  case 1: {
    g();
  };
  case 2:
    h();
    break;
  }
}
