/*
 * Rule: DCL19-C
 * Source: real-world FP pattern
 * Status: PASS - STATIC macro is a conditional alias for static
 *
 * The STATIC macro expands to `static` in production and to nothing in
 * test builds.  Functions declared with STATIC already have internal
 * linkage and should not be flagged.
 */

#define STATIC static

STATIC int helper(int x) {
  return x + 1;
}

int caller(void) {
  return helper(42);
}
