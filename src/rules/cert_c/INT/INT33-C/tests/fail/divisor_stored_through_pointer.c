/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The divisor is overwritten through a pointer to it
 *
 * `x` starts at 1, but the store through `q` replaces it with a value the
 * function cannot bound, and nothing checks it before the division.
 */

int read_untrusted(void);

int ratio(void)
{
    int x = 1;
    int *q = &x;
    *q = read_untrusted();
    return 100 / x;
}
