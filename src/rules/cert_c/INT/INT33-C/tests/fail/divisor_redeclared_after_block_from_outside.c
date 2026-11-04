/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - A variable declared again after a block has its own value
 * Expect: count=2
 *
 * The block's `x` is 5, but the `x` declared after it is read from outside.
 * The second loop's own `i` starts at zero, whatever the first loop's `i`
 * counted from.
 */

int read_untrusted(void);

int reused_after(void)
{
    {
        int x = 5;
        (void)x;
    }
    int x = read_untrusted();
    return 100 / x; /* Expect: here */
}

int sibling_loops(void)
{
    int s = 0;
    for (int i = 1; i < 5; i++)
        s += 100 / i;
    for (int i = 0; i < 5; i++)
        s += 100 / i; /* Expect: here */
    return s;
}
