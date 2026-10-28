/*
 * Rule: MSC37-C
 * Source: aurora-lint
 * Status: PASS - `STATIC struct { ... } s_state;` declares an object, not a
 *         function
 */

#define STATIC static

STATIC struct {
  int a;
} s_state;

int read_state(void) {
  return s_state.a;
}
