/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A macro takes the pointer's address
 *
 * `*PP = &t` repoints `q` through the address `PP` takes, so `*q = 2`
 * leaves `s` at 40.
 */

#define PP (&q)

int t;

int mask(void)
{
    int s = 40;
    int *q = &s;
    *PP = &t;
    *q = 2;
    return 1 << s;
}
