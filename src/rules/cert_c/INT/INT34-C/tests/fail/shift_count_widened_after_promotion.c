/*
 * Rule: INT34-C
 * Status: FAIL - the count 32 is the full width of the int the operand
 * promotes to
 * Settings: data_model=lp64
 */

int shift_char_by_32(unsigned char ch)
{
    unsigned int i = 32;
    return ch << i;
}
