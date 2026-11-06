/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - The pointer may hold a file-scope object's address instead
 *
 * `q` holds the address of `g` unless `c` is set, so `*q = 2` may leave
 * `s` at 40.
 */

int g;

int mask(int c)
{
    int s = 40;
    int *q = &g;
    if (c)
        q = &s;
    *q = 2;
    return 1 << s;
}
