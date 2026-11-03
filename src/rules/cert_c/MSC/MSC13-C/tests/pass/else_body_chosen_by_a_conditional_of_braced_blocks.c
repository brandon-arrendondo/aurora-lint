/*
 * Rule: MSC13-C
 * Source: synthetic reduction of an if/else whose else body is picked by
 *   a conditional of one braced block per arm
 * Status: PASS - Should NOT trigger MSC13-C violation
 *
 * The braced blocks after the second `#if` are the else body of
 * `if (hash == 1)`, so `ret = 384` is read by the return whenever that arm
 * runs. Left unrepaired, the `else` is a parse error and the blocks read
 * as statements after the if that overwrite it.
 */
int pick(int hash)
{
    int ret;
#if defined(HAVE_SHA384)
    if (hash == 1) {
        ret = 384;
    } else
#endif
#if defined(HAVE_SHA256)
    {
        ret = 256;
    }
#else
    {
        ret = -1;
    }
#endif
    return ret;
}
