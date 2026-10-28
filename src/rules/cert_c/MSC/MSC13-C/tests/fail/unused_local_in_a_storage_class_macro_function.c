/*
 * Rule: MSC13-C
 * Source: aurora-lint
 * Status: FAIL - an unused local in a function declared through a
 *         storage-class macro
 * Expect: count=1
 */

#define STATIC static

typedef int myint;

STATIC myint helper(void) {
  int unused; /* Expect: here */
  return 2;
}

int caller(void) {
  return helper();
}
