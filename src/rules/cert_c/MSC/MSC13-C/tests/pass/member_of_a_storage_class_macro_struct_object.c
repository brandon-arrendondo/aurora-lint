/*
 * Rule: MSC13-C
 * Source: aurora-lint
 * Status: PASS - `a` is a member of the object s_state, not a local
 */

#define STATIC static

STATIC struct {
  int a;
} s_state;

int read_state(void) {
  return s_state.a;
}
