/*
 * Rule: MSC37-C
 * Source: aurora-lint
 * Status: PASS - `SHARED struct { ... } g_shared;` with SHARED expanding to
 *         extern declares an object, not a function
 */

#define SHARED extern

SHARED struct {
  int a;
} g_shared;

int read_shared(void) {
  return g_shared.a;
}
