/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A second chain on the same macro undoes the store
 *
 * No configuration holds 9 at the access.
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
    i = 1;
#endif
    return buf[i];
}
