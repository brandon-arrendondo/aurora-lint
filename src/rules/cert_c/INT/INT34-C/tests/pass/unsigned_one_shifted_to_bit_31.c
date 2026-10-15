/*
 * Rule: INT34-C
 * Status: PASS - 31 is below the precision of a 32-bit unsigned int
 * Settings: data_model=lp64
 */

unsigned int top_bit(void)
{
    return 1u << 31;
}
