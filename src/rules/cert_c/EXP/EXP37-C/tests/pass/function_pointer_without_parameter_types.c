/*
 * Rule: EXP37-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP37-C violation
 *
 * A function pointer declared with `()` is reported, if at all, at a call
 * that mismatches the function it holds. This call matches.
 */

int next_id(void);

int (*fp)() = next_id;

int take(void) {
  return fp();
}
