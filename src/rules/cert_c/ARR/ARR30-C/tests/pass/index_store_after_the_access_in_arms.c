/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A store after the access does not reach it
 *
 * Both arms are in bounds at the access, and the store of 9 runs after it.
 */

int buf[4];

int element(void)
{
#if defined(A)
    int i = 1;
#else
    int i = 2;
#endif
    int r = buf[i];
    i = 9;
    return r + i;
}
