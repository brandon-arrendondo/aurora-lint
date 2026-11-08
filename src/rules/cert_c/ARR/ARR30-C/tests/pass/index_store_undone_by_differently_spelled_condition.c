/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - A second chain on the same macro, spelled differently, undoes the store
 *
 * No configuration holds 9 at the access.
 */

int buf[4];
int c;

int element(void)
{
    int i = 1;
#ifdef A
    i = 9;
#endif
#if defined(A)
    i = 1;
#endif
    return buf[i];
}
