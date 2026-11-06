/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A macro that names the pointer repoints it
 *
 * `RP` assigns `q` by name, though no occurrence of `q` shows it, so
 * `*q = 2` writes `t` and leaves `s` at 40.
 */

#define RP() (q = &t)

int t;

int mask(void)
{
    int s = 40;
    int *q = &s;
    RP();
    *q = 2;
    return 1 << s;
}
