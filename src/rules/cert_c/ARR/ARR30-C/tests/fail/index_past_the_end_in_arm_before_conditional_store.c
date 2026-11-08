/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A conditional store does not decide the arms' values
 * Expect: count=1
 *
 * The store may not run, so the #if arm's 9 can still reach the access.
 */

int buf[4];

int element(int c)
{
#if defined(A)
    int i = 9;
#else
    int i = 1;
#endif
    if (c)
        i = 2;
    return buf[i];
}
