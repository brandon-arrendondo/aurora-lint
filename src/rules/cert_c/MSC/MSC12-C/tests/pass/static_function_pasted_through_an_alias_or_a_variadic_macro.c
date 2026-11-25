/*
 * Rule: MSC12-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger MSC12-C violation
 *
 * Each call pastes the static's name through a macro that hands its
 * arguments to CAT: an object-like alias (PASTE), a variadic macro whose
 * __VA_ARGS__ are CAT's arguments (CALL), and XCAT, handed an object-like
 * macro (PREFIX) whose expansion is the fragment.
 */

#define CAT(a, b) a##b
#define XCAT(a, b) CAT(a, b)
#define PASTE CAT
#define CALL(...) CAT(__VA_ARGS__)
#define PREFIX mod

static int foo_x(void) { return 1; }
static int foo_h(void) { return 2; }
static int mod_init(void) { return 3; }

int api(void) { return PASTE(foo, _x)() + CALL(foo, _h)() + XCAT(PREFIX, _init)(); }
