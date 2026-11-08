/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - A conditional store past the end after the arms
 * Expect: count=1
 *
 * The arms are in bounds, and the store that may run is not.
 */

int buf[4];

int element(int c)
{
#if defined(A)
    int i = 2;
#else
    int i = 1;
#endif
    if (c)
        i = 9;
    return buf[i];
}
