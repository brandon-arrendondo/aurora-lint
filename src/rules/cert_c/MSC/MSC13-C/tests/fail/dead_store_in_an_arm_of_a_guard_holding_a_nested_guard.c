/*
 * Rule: MSC13-C
 * Source: synthetic reduction of an if/else split across a feature guard
 *   whose braced arm holds a guarded if/else of its own
 * Status: FAIL - Should trigger MSC13-C violation
 * Expect: count=1
 *
 * Fail twin of the pass fixture of the same shape: once the chain parses,
 * a store inside the guarded arm that is overwritten before any read is
 * still reported.
 */
int use(int v);

int f(int t, int n, int c)
{
    int off;
    int len;
#if defined(HAVE_A)
    if (t == 1) {
        len = 4; /* Expect: here */
        len = n;
#if defined(HAVE_B)
        if (c != 0) {
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
