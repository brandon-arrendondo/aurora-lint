/*
 * Rule: INT34-C
 * Status: FAIL - a literal amount of 40 for a 32-bit unsigned int
 * Settings: data_model=lp64
 *
 * A constant amount is judged by its value like any other: shifting by 40
 * is undefined whether or not a compiler would warn about it.
 */

unsigned int shift_literal(unsigned int x)
{
    return x >> 40;
}
