/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS - Each arm divides by the variable it means
 *
 * One arm of the conditional declares a block's own `x` from outside and
 * checks it before dividing. The other arm only assigns `x`, which there
 * is the function's `x`, and gives it a nonzero constant before dividing.
 * After the block the function's `x` is nonzero on every path.
 */

int read_untrusted(void);

int ratio(void)
{
    int x = 1;
    {
#ifdef A
        int x = read_untrusted();
        if (x == 0)
            return 0;
        (void)(10 / x);
#else
        x = 3;
        (void)(10 / x);
#endif
    }
    return 10 / x;
}
