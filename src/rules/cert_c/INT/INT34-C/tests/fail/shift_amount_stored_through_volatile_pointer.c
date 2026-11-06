/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A volatile pointer may hold another address by the store
 *
 * `q` is volatile, so it may not hold `&s` when `*q = 2` runs.
 */

int mask(void)
{
    int s = 40;
    int *volatile q = &s;
    *q = 2;
    return 1 << s;
}
