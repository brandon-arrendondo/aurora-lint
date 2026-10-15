/*
 * Rule: INT34-C
 * Status: FAIL - a #define amount of 40 for a 32-bit unsigned int
 * Settings: data_model=lp64
 */

#define SHIFT 40

unsigned int shift_by_macro(unsigned int x)
{
    return x >> SHIFT;
}
