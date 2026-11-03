/*
 * Rule: EXP19-C
 * Source: synthetic reduction of an if/else split across a feature guard
 *   whose braced arm holds a guarded if/else of its own
 * Status: FAIL - Should trigger EXP19-C violation
 * Expect: count=1
 *
 * The statement after the outer `#endif` is the else body of
 * `if (t == 1)`, and it is not braced. Left unrepaired, the `} else` is a
 * parse error and the statement reads as one of its own after the if.
 */
int use(int v);

int f(int t, int n, int c)
{
    int off;
#if defined(HAVE_A)
    if (t == 1) {
#if defined(HAVE_B)
        if (c != 0) {
            use(1);
        } else
#endif
        {
            use(2);
        }
        off = n + 1;
    } else
#endif
    off = n + 2; /* Expect: here */
    return use(off);
}
