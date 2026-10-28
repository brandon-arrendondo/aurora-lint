/*
 * Rule: DCL15-C
 * Source: aurora-lint
 * Status: FAIL - in the UNIT_TEST build STATIC expands to nothing
 * Expect: count=1
 *
 * Not every definition of STATIC is `static`, so the function keeps the
 * external linkage the test build gives it.
 */

#ifdef UNIT_TEST
#define STATIC
#else
#define STATIC static
#endif

typedef int myint;

STATIC myint helper(void) { /* Expect: here */
  return 2;
}

static int caller(void) {
  return helper();
}
