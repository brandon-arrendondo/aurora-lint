/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - The pointer is repointed through a pointer to it
 *
 * `*pp = &b` makes `q` point at `b`, so `*q = 2` leaves `s` at 40.
 */

int b;

int mask(void)
{
    int s = 40;
    int *q = &s;
    int **pp = &q;
    *pp = &b;
    *q = 2;
    return 1 << s;
}
