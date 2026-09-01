/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation.
 * `deliberate_fall_through` is sqlite's portable fallthrough-annotation
 * macro, `#define`d (to nothing, or to a self-terminated
 * `__attribute__((fallthrough));`) in a header this file never includes --
 * so there is no LOCAL `#define` for this pass to find. Left unblanked,
 * the bare identifier immediately preceding the `case 1:` label (no
 * separating `;`) sends tree-sitter-c into ERROR recovery that invents a
 * bogus declaration whose declared name is literally `case`, which
 * EXP33-C's init-state analysis then tracks as an uninitialized variable
 * and flags wherever the real `case` keyword reappears later in the same
 * function (task 461 category 8; sqlite's vdbe.c byte-serialization
 * switch).
 */
void f(int len, unsigned char *z, unsigned long long v) {
    switch (len) {
        default: z[1] = (unsigned char)v; v >>= 8;
                 /* no break */ deliberate_fall_through
        case 1:  z[0] = (unsigned char)v;
    }
}
