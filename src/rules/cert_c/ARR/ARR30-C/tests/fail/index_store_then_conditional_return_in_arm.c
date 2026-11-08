/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - The arm stores past the end and may return
 * Expect: count=1
 *
 * On the path that does not return, the store reaches the access.
 */

int buf[4];
int c;

int element(void)
{
    int i = 1;
#if A
    i = 9;
    if (c) {
        return 0;
    }
#endif
    return buf[i];
}
