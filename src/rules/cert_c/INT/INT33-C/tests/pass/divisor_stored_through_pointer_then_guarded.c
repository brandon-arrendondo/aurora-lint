/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - The divisor is overwritten through a pointer, then checked
 *
 * The store through `q` may make `x` anything, and the early return leaves
 * only the positive values for the division.
 */

int read_untrusted(void);

int ratio(void)
{
    int x = 1;
    int *q = &x;
    *q = read_untrusted();
    if (x < 1)
        return 0;
    return 100 / x;
}
