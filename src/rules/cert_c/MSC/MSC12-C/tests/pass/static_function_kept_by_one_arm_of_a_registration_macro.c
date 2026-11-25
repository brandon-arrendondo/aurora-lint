/*
 * Rule: MSC12-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger MSC12-C violation
 *
 * One arm defines REG as a whole constructor, an item of its own; the other,
 * the one a build with no -D compiles, as `__attribute__((used))`, which
 * keeps the static after it. Only when every arm's expansion ends an item
 * is the invocation left out of the static's head.
 */

#ifdef USE_CTOR
#define REG(fn) static void __attribute__((constructor)) reg_##fn(void) { (void)fn; }
#else
#define REG(fn) __attribute__((used))
#endif

REG(x)
static int maybe_kept(void) { return 1; }

int api(void) { return 0; }
