/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - After the store, a nested chain returns in every arm
 *
 * The store never reaches the access.
 */

int buf[4];
int c;

int element(void)
{
    int i = 1;
#if A
    i = 9;
#if B
    return 1;
#else
    return 2;
#endif
#endif
    return buf[i];
}
