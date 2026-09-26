/*
 * Rule: DCL15-C
 * Source: testcases
 * Status: FAIL - Should trigger DCL15-C violation
 *
 * PRIVATE is spelled like a linkage macro, but its `#define` expands to
 * nothing, so helper has external linkage. The spelling alone does not make
 * it static.
 */

#define PRIVATE

PRIVATE int helper(int x) {
  return x + 1;
}

static int caller(void) {
  return helper(42);
}
