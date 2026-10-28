/*
 * Rule: DCL15-C
 * Source: aurora-lint
 * Status: PASS - STATIC expands to static, so the function has internal
 *         linkage even though its return type is a typedef name
 */

#define STATIC static

typedef int myint;

STATIC myint helper(void) {
  return 2;
}

static int caller(void) {
  return helper();
}
