/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: `(u32) (a + b)` casts a parenthesized operand to the typedef
 * u32; a C parser reads it as a call through `(u32)`, but nothing is
 * called and the argument has no side effect. The same with no space, and
 * with a typedef this file names otherwise.
 */

typedef unsigned int u32;
typedef unsigned int myu32;

#define TWICE(x) ((x) + (x))
#define swab32(x) ((((x) & 0xff) << 24) | (((x) >> 24) & 0xff))

u32 spaced(u32 a, u32 b) {
    return TWICE((u32) (a + b));
}

u32 unspaced(u32 a, u32 b) {
    return TWICE((u32)(a+b));
}

myu32 local_typedef(myu32 a, myu32 b) {
    return TWICE((myu32) (a + b));
}

u32 header_word(u32 flags, u32 hdrlen, u32 len) {
    return swab32(((u32) flags << 24) | (u32) (hdrlen + len));
}
