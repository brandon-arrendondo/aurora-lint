/*
 * Rule: MSC37-C
 * Source: aurora-lint
 * Status: FAIL - a function declared through a storage-class macro still
 *         needs its return
 * Expect: count=1
 */

#define STATIC static

typedef int myint;

STATIC myint helper(int x) { /* Expect: here */
  if (x > 0) {
    return x;
  }
}

int caller(void) {
  return helper(1);
}
