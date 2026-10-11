/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - The divisor stays non-zero through the writes between
 *
 * Writing a non-zero constant after the zero guard keeps the divisor
 * non-zero, and a field assigned a value already proven non-zero is
 * non-zero at the division.
 */

struct range {
    int step;
};

long remainder_of(long b, long a)
{
    if (a == 0)
        return 0;
    if (a == -1)
        a = 1;
    b %= a;
    return b;
}

int count(struct range *r, int lo, int hi, int step)
{
    if (!step)
        return -1;
    r->step = step;
    return (hi - lo) / r->step;
}
