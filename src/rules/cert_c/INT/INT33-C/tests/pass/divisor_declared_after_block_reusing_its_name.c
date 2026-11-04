/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - A name declared again after a block is a new variable
 *
 * The block's `x` is zero and goes out of scope; the `x` declared after it
 * is 5, and so is the divisor. Two loops that each declare `i` count from
 * 1 and from 2, and neither divides by zero.
 */

int reused_after(void)
{
    {
        int x = 0;
        (void)x;
    }
    int x = 5;
    return 100 / x;
}

int sibling_loops(void)
{
    int s = 0;
    for (int i = 0; i < 5; i++)
        s += i;
    for (int i = 2; i < 5; i++)
        s += 100 / i;
    return s;
}
