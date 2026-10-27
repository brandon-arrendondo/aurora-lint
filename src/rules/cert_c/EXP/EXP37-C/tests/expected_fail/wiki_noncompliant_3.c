/*
 * Rule: EXP37-C
 * Source: wiki
 * Status: EXPECTED_FAIL - the no-prototype-call form, not detected yet
 *
 * The violation is the call `f(x)`, an int passed where the definition
 * takes a long with no prototype in scope (before C23). The old report at
 * the `long f();` declaration is DCL20-C's construct.
 */

/* In another source file */
long f(long x) {
  return x < 0 ? -x : x;
}

/* In this source file, no f prototype in scope */
long f();
 
long g(int x) {
  return f(x);
}