/*
 * Rule: INT34-C
 * Status: FAIL - an enumerator amount of 40 for a 32-bit unsigned int
 * Settings: data_model=lp64
 */

enum { SHIFT = 40 };

unsigned int shift_by_enumerator(unsigned int x)
{
    return x >> SHIFT;
}
