/*
 * Rule: INT34-C
 * Status: FAIL - one of the counts the shift can take is 40
 * Settings: data_model=lp64
 */

unsigned int shift_by_3_or_40(unsigned int x, int c)
{
    unsigned int i = c ? 3 : 40;
    return x >> i;
}
