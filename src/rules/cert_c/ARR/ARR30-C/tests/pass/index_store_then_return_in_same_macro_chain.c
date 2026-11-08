/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A second chain on the same macro returns after the store
 *
 * No configuration reaches the access holding 9.
 */

int buf[4];
int c;

int element(void)
{
    int i = 1;
#if A
    i = 9;
#endif
#if A
    return 0;
#endif
    return buf[i];
}
