/*
 * Rule: MSC12-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger MSC12-C violation
 *
 * The call pastes the static's name from a macro's arguments: CAT(bar, _cb)
 * expands to bar_cb, and HANDLER(foo) hands foo to CAT, which pastes
 * foo_handler.
 */

#define CAT(a, b) a##b
#define HANDLER(n) CAT(n, _handler)

static int foo_handler(void) { return 1; }
static int bar_cb(void) { return 2; }

int api(void) { return HANDLER(foo)() + CAT(bar, _cb)(); }
