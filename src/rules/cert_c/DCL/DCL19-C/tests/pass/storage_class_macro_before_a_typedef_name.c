/*
 * Rule: DCL19-C
 * Source: aurora-lint
 * Status: PASS - STATIC expands to static, so the function already has the
 *         narrowest scope
 */

#define STATIC static

typedef int myint;

STATIC myint helper(void) {
  return 2;
}

static int caller(void) {
  return helper();
}
