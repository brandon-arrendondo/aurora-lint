/*
 * Rule: INT08-C
 * Source: task 755 (residual FP classes found re-measuring the promoted-range fix)
 * Status: PASS - Should NOT trigger INT08-C violation
 *
 * Each case pairs a narrow (char/short) operand with something whose range
 * const_eval cannot resolve. The rule used to fall back to a guard-text
 * heuristic here and re-emit the same inverted premise it was fixed for --
 * 66 findings still stood across the pinned real-world corpus, mostly these
 * three shapes. The overflow risk in every one of them, if there is any,
 * belongs to the *wide* operand and is INT32-C's concern; the narrow operand
 * contributes at most a few hundred to the product.
 */

#include <stdlib.h>

/* Case 1: narrow operand times an unbounded int parameter
 * (sqlite ext/misc/decimal.c, curl lib/mqtt.c). */
int mul_by_unbounded_param(int n) {
    unsigned char b = 7;
    return b * n;
}

/* Case 2: narrow operand times an unresolvable call result. */
int mul_by_call_result(void) {
    unsigned char b = 7;
    return b * rand();
}

/* Case 3: shift by a non-constant amount (raylib src/rtextures.c). */
int shift_by_variable(int n) {
    unsigned short s = 3;
    return s << n;
}

/* Case 4: floating-point arithmetic that merely happens to contain a narrow
 * operand -- not integer overflow at all (raylib src/rtextures.c, where the
 * shape is `(float)((pixel & 0xf800) >> 11)*(1.0f/31)`). */
float scale_narrow_to_float(unsigned short pixel) {
    unsigned short masked = pixel;
    return (float)masked * (1.0f / 31);
}
