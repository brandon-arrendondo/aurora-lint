/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The arm storing past the end returns
 *
 * The store never reaches the access.
 */

int buf[4];
int c;

int element(void)
{
    int i;
#if A
    i = 9;
    return i;
#else
    i = 1;
#endif
    return buf[i];
}
