/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Expect: default=clean strict=clean
 * Reason: each cast names its type through an object-like macro: one whose
 * body is type keywords (`#define u32 unsigned int`), and one naming a
 * typedef (`#define U32 myu32`). A C parser reads `(u32) (a + b)` as a call
 * through `(u32)`, but nothing is called.
 */

#define u32 unsigned int
typedef unsigned int myu32;
#define U32 myu32

#define TWICE(x) ((x) + (x))

u32 keywords(u32 a, u32 b) {
    return TWICE((u32) (a + b));
}

U32 aliased(U32 a, U32 b) {
    return TWICE((U32)(a + 1));
}
