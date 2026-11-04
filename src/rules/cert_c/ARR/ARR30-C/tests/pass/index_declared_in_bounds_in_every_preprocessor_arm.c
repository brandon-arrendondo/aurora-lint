/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - Every preprocessor arm declares the index in bounds
 *
 * The index is declared once in each arm of a conditional, each time with
 * a constant inside the array, so whichever arm is built reads in bounds.
 */

int buf[3];

int element(void)
{
#if defined(BIG)
    int i = 1;
#else
    int i = 2;
#endif
    return buf[i];
}
