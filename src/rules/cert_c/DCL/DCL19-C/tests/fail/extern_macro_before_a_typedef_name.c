/*
 * Rule: DCL19-C
 * Source: aurora-lint
 * Status: FAIL - EXPORTED expands to extern, so the function has external
 *         linkage, and only this file calls it
 * Expect: count=1
 */

#define EXPORTED extern

typedef int myint;

EXPORTED myint helper(void) { /* Expect: here */
  return 2;
}

static int caller(void) {
  return helper();
}
