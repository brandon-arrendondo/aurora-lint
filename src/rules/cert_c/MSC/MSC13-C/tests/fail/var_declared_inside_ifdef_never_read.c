/*
 * Rule: MSC13-C
 * Source: task 386 follow-up companion (2026-08-28)
 * Status: FAIL - Should trigger MSC13-C violation
 *
 * Companion to var_declared_and_used_inside_ifdef.c (pass): the fix that
 * makes a declaration inside a #ifdef resolve correctly must not over-
 * correct into never flagging any #ifdef-nested variable at all. One that
 * is genuinely never read is still a real violation.
 */

static int f(int x) {
#ifdef NEED_AP_MLME
  int unused_var;
  unused_var = x;
  return 0;
#else
  return 0;
#endif
}
