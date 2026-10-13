/*
 * Rule: INT34-C
 * Status: FAIL - the shift count is 39 for a 32-bit operand
 * Settings: data_model=lp64
 *
 * The count is a variable, not a literal, and the range analysis pins it to
 * one value. A single value at or above the width is as undefined as any
 * range that reaches it.
 */

unsigned int shift_by_39(unsigned int x)
{
    unsigned int i = 39;
    return x >> i;
}
