/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - Each division is proven non-zero by what control passed
 *
 * An if/else whose zero arm returns, a loop that runs until the divisor is
 * non-zero, and operands proven distinct.
 */

int read_value(void);

int else_arm_continues(int a, int d)
{
    int r;
    if (d == 0)
        return 0;
    else
        r = 1;
    return r + a / d;
}

int read_until_nonzero(int a)
{
    int d = read_value();
    while (d == 0)
        d = read_value();
    return a / d;
}

int distinct_operands(int v, int hi, int lo)
{
    if (hi != lo)
        return v / (hi - lo);
    return 0;
}

int ordered_by_early_return(int v, int hi, int lo)
{
    if (hi <= lo)
        return 0;
    return v / (hi - lo);
}
