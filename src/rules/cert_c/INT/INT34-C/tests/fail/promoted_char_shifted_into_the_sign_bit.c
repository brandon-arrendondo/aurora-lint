/*
 * Rule: INT34-C
 * Status: FAIL - an unsigned char promotes to a signed int of precision 31
 * Settings: data_model=lp64
 */

int char_to_sign_bit(unsigned char c)
{
    return c << 31;
}
