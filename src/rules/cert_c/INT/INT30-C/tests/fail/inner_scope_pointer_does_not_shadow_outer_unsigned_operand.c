/*
 * Rule: INT30-C
 * Source: regression
 * Status: FAIL - `x + m` adds two unsigned ints without a wrap check
 *
 * An inner block declares its own `char *x`. A function-wide name map keeps
 * one entry per name, and the inner declaration used to answer for the
 * outer `x`, so the addition read as pointer arithmetic and was skipped. The
 * occurrence's own declaration is the outer unsigned int.
 */

unsigned int next_count(unsigned int n, unsigned int m)
{
    unsigned int x = n;
    unsigned int r = x + m;
    {
        char *x = 0;
        (void)x;
    }
    return r;
}
