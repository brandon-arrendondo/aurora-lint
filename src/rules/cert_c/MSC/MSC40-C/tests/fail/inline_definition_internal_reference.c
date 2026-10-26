/*
 * Rule: MSC40-C
 * Source: synthetic
 * Status: FAIL - Should trigger MSC40-C violation
 *
 * An inline definition with external linkage refers to an identifier with
 * internal linkage. `__inline__` is the GNU spelling of `inline`.
 */

static int seed = 1;

__inline__ int scaled(int a) {
  return a * seed;
}
