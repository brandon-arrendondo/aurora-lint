/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - The access uses its own arm's index
 * Expect: count=1
 *
 * The other arm's in-bounds value is not this arm's.
 */

int buf[4];

int element(void)
{
#if defined(A)
    int i = 9;
    return buf[i];
#else
    int i = 1;
    return i;
#endif
}
