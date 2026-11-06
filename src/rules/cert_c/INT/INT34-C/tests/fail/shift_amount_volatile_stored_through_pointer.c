/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A volatile amount may change after the store through the pointer
 *
 * `s` is volatile, so the value the shift reads need not be the 2 just
 * stored.
 */

int mask(void)
{
    volatile int s = 40;
    volatile int *q = &s;
    *q = 2;
    return 1 << s;
}
