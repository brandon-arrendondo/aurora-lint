/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - An arm that only assigns the name assigns the outer variable, not the one another arm declares
 * Expect: count=2
 *
 * In each function one arm of a conditional declares a block's own `x`,
 * and a later arm only assigns `x`. A declaration in one arm is not in
 * scope in another, so that assignment writes the function's `x`, which
 * after the block is read from outside and never checked.
 */

int read_untrusted(void);

int ratio_else_arm(void)
{
    int x = 1;
    {
#ifdef A
        int x = 4;
        (void)x;
#else
        x = read_untrusted();
#endif
    }
    return 10 / x; /* Expect: here */
}

int ratio_elif_arm(void)
{
    int x = 1;
    {
#if defined(A)
        int x = 4;
        (void)x;
#elif defined(B)
        x = read_untrusted();
#else
        x = 2;
#endif
    }
    return 10 / x; /* Expect: here */
}
