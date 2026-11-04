/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - The divisor keeps its constant past a block that widens its own variable
 *
 * Each inner block declares its own `x` and gives it a value read from
 * outside, by assignment or by a store through a pointer to it. The outer
 * `x` the division reads is another object and is still 1 there.
 */

int read_untrusted(void);

int ratio_after_assignment(void)
{
    int x = 1;
    {
        int x = 2;
        x = read_untrusted();
        (void)x;
    }
    return 100 / x;
}

int ratio_after_store(void)
{
    int x = 1;
    {
        int x = 2;
        int *q = &x;
        *q = read_untrusted();
        (void)x;
    }
    return 100 / x;
}
