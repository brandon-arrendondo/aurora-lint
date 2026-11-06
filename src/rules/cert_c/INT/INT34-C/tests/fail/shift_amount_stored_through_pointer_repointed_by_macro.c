/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A macro the pointer is handed to repoints it
 *
 * `REPOINT` expands to an assignment of `q`, so `*q = 2` writes `t` and
 * leaves `s` at 40.
 */

#define REPOINT(p, t) ((p) = (t))

int t;

int mask(void)
{
    int s = 40;
    int *q = &s;
    REPOINT(q, &t);
    *q = 2;
    return 1 << s;
}
