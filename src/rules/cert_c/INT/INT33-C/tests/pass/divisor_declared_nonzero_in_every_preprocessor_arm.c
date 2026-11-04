/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - Every preprocessor arm declares the divisor nonzero
 *
 * The divisor is declared once in each arm of a conditional, each time
 * with a nonzero constant, so whichever arm is built divides by a
 * nonzero value.
 */

int ratio(void)
{
#ifdef LARGE
    int x = 8;
#else
    int x = 4;
#endif
    return 10 / x;
}
