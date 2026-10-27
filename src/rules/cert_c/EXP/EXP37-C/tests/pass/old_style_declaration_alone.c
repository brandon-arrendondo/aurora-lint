/*
 * Rule: EXP37-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP37-C violation
 *
 * An old-style declaration on its own is DCL20-C's construct. This rule
 * is about a call, and the only call here matches the definition.
 */

long magnitude();

long magnitude(long x) {
  return x < 0 ? -x : x;
}

long use(void) {
  return magnitude(5L);
}
