/*
 * Rule: DCL15-C
 * Source: aurora-lint
 * Status: FAIL - STATIC is only a default, which -DSTATIC= replaces
 * Expect: count=1
 *
 * A build that defines STATIC as nothing compiles the function with
 * external linkage, so it is not read as static.
 */

#ifndef STATIC
#define STATIC static
#endif

typedef int myint;

STATIC myint helper(void) { /* Expect: here */
  return 2;
}

static int caller(void) {
  return helper();
}
