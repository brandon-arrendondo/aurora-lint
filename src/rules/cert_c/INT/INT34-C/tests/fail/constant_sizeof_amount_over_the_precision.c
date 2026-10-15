/*
 * Rule: INT34-C
 * Status: FAIL - a sizeof-derived amount of 64 for a 32-bit unsigned int
 * Settings: data_model=lp64
 */

unsigned int shift_by_bits_of_long_long(unsigned int x)
{
    return x >> (sizeof(long long) * 8);
}
