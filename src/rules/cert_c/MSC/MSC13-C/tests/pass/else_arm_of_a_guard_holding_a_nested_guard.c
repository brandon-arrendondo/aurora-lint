/*
 * Rule: MSC13-C
 * Source: synthetic reduction of an if/else split across a feature guard
 *   whose braced arm holds a guarded if/else of its own
 * Status: PASS - Should NOT trigger MSC13-C violation
 *
 * The statement after the outer `#endif` is the else body of
 * `if (t == 1)`, so `off = len + 1` is read by the return whenever that
 * arm runs. Left unrepaired, both `} else` lines are parse errors and the
 * else body reads as an unconditional overwrite of `off`.
 */
int use(int v);

int f(int t, int n, int c, int r)
{
    int off;
    int len;
#if defined(HAVE_A)
    if (t == 1) {
        len = n;
#if defined(HAVE_B)
        if (c != 0
#if defined(HAVE_C)
            && r == 0
#endif
            ) {
            use(1);
        } else
#endif
        {
            use(2);
        }
        off = len + 1;
    } else
#endif
    off = n + 2;
    return use(off);
}
