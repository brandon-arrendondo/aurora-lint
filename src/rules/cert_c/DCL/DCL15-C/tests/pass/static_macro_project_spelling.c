/*
 * Rule: DCL15-C
 * Source: testcases
 * Status: PASS - Should NOT trigger DCL15-C violation
 *
 * LOCAL_FN is this project's own spelling for internal linkage. Its
 * `#define` expands to `static inline`, so the helper already has internal
 * linkage. What makes the prefix `static` is the definition, not a list of
 * familiar names.
 */

#define LOCAL_FN static inline

LOCAL_FN int helper(int x) {
  return x + 1;
}

static int caller(void) {
  return helper(42);
}
