/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - Every value after a conditional store is in bounds
 *
 * The arms and the store that may run all leave an index in bounds.
 */

int buf[4];

int element(int c)
{
#if defined(A)
    int i = 3;
#else
    int i = 1;
#endif
    if (c)
        i = 2;
    return buf[i];
}
