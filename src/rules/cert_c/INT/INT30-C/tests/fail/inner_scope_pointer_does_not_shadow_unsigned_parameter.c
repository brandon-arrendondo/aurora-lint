/*
 * Rule: INT30-C
 * Source: regression
 * Status: FAIL - `x + n` adds two unsigned int parameters without a wrap check
 *
 * An inner block declares its own `char *x`. A function-wide name map records
 * the parameter and the inner local under one name, and the inner local used
 * to answer for the parameter, so the addition read as pointer arithmetic and
 * was skipped. The occurrence's own declaration is the parameter.
 */

unsigned int next_count(unsigned int x, unsigned int n)
{
    unsigned int r = x + n;
    {
        char *x = 0;
        (void)x;
    }
    return r;
}
