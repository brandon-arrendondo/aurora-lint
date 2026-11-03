/*
 * Rule: MSC13-C
 * Source: synthetic reduction of an if/else whose else body is picked by
 *   a conditional of one braced block per arm
 * Status: FAIL - Should trigger MSC13-C violation
 * Expect: count=1
 *
 * Fail twin of the pass fixture of the same shape: once the else body is
 * joined, a store in it that is overwritten before any read is still
 * reported, and the if arm's store is not.
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
        ret = 0; /* Expect: here */
        ret = 256;
    }
#else
    {
        ret = -1;
    }
#endif
    return ret;
}
