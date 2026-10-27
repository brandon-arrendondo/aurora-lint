/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Expect: default=clean strict=clean
 * Reason: add's body casts a parenthesized operand, (u32) (a + b), which a
 * C parser reads as a call through (u32). u32 is a typedef, so it is a cast,
 * add calls nothing, and TWICE(add(a, b)) evaluates no side effect twice.
 */

typedef unsigned int u32;

#define TWICE(x) ((x) + (x))

static u32 add(u32 a, u32 b) {
    return (u32) (a + b);
}

u32 use(u32 a, u32 b) {
    return TWICE(add(a, b));
}
