/*
 * Rule: MSC13-C
 * Source: synthetic reduction of an if/else split across a feature guard
 *   whose braced arm picks one of two calls with a conditional of its own
 * Status: PASS - Should NOT trigger MSC13-C violation
 *
 * The block after `#endif` is the else body of `if (mode == 1)`, so the
 * value stored in either arm of the inner conditional is read by the
 * return whenever that arm runs.
 */
int legacy(int v);
int modern(int v);

int f(int mode, int v)
{
    int ret;
#if defined(HAVE_FAST)
    if (mode == 1) {
#if defined(USE_MODERN)
        ret = modern(v);
#else
        ret = legacy(v);
#endif
    } else
#endif
    {
        ret = -1;
    }
    return ret;
}
