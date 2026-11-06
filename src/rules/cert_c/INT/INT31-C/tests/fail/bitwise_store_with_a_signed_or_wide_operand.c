/*
 * Rule: INT31-C
 * Source: synthetic
 * Status: FAIL - A bitwise result no operand bounds does not fit the narrower target
 * Expect: count=2
 *
 * A negative `short` has its high bits set, so clearing one bit of it can
 * leave a value no `short` holds once the `int` mask is applied. `a | b`
 * needs both operands inside the target, and an `int` is not.
 */

#include <stdint.h>

#define MODIFIER_MASK (1 << 15)

void sink(int);

void signed_left(short flags, int wide, uint8_t byte)
{
    flags &= ~MODIFIER_MASK;   /* Expect: here */
    uint8_t low = wide | byte; /* Expect: here */
    uint8_t kept = wide & byte;
    sink(flags + low + kept);
}
