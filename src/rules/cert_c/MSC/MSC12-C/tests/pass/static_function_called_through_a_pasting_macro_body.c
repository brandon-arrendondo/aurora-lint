/*
 * Rule: MSC12-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger MSC12-C violation
 *
 * The pasting call is written in another macro's body: CALL_FOO() expands
 * to CAT(foo, _x)(), which calls foo_x, and CALL_BAR(v) to bar_y(v).
 */

#define CAT(a, b) a##b
#define CALL_FOO() CAT(foo, _x)()
#define CALL_BAR(v) CAT(bar, _y)(v)

static int foo_x(void) { return 1; }
static int bar_y(int v) { return v; }

int api(void) { return CALL_FOO() + CALL_BAR(2); }
