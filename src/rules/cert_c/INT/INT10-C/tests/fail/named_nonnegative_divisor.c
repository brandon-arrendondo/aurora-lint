/*
 * Rule: INT10-C
 * Source: task 777
 * Status: FAIL - Should trigger INT10-C violation
 *
 * A non-negative DIVISOR proves nothing about the remainder's sign. C99
 * 6.5.5p6 truncates toward zero, so `a % b` carries the sign of `a`:
 * -5 % 8 == -5, whatever 8's sign is.
 *
 * is_potentially_signed_modulo used to accept EITHER operand resolving to a
 * non-negative compile-time constant as grounds to suppress, which swallowed
 * this whole class silently. Only the dividend half (task 673) is sound.
 *
 * Bare integer literals are deliberately excluded from that resolution, so
 * the divisor here has to be NAMED to exercise the bug -- which is also how
 * real code spells it.
 */

#define GRANULE 8

int offset_within_granule(int delta)
{
    return delta % GRANULE; /* VIOLATION: delta may be negative */
}
