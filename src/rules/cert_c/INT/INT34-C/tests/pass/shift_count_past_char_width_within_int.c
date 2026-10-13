/*
 * Rule: INT34-C
 * Status: PASS - the count is below the width of the promoted operand
 * Settings: data_model=lp64
 *
 * An unsigned char operand promotes to int, so the bound is int's 32 bits,
 * not the char's 8: a count of 20 is defined.
 */

int shift_char_by_20(unsigned char ch)
{
    unsigned int i = 20;
    return ch << i;
}
