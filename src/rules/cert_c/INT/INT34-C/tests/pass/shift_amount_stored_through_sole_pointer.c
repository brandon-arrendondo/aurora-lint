/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: PASS - The store through the only pointer to the amount replaces it
 *
 * `q` holds the address of `s` and nothing else, so `*q = 2` leaves `s`
 * holding 2, not 40 or 2.
 */

int mask(void)
{
    int s = 40;
    int *q = &s;
    *q = 2;
    return 1 << s;
}
