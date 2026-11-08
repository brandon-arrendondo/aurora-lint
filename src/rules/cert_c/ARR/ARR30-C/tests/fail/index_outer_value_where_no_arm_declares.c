/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A build with neither macro uses the outer index
 * Expect: count=1
 *
 * Neither arm declares the index when A and B are both undefined, so the
 * access uses the outer 9.
 */

int buf[4];

int element(void)
{
    int i = 9;
    {
#if defined(A)
        int i = 1;
#elif defined(B)
        int i = 2;
#endif
        return buf[i];
    }
}
