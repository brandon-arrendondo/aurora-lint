/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - An index both ways of an if/else write past the end, whatever it started as
 * Expect: count=2
 *
 * `i` starts at 0, in bounds, but both ways overwrite it, with 7 or 8,
 * before the access, so `buf[i]` reads past the end of `buf[5]` on every
 * path. The initializer reaches no access and proves nothing about it.
 */

int braced(int c)
{
    int buf[5] = {0};
    int i = 0;
    if (c) {
        i = 7;
    } else {
        i = 8;
    }
    return buf[i]; /* Expect: here */
}

int unbraced(int c)
{
    int buf[5] = {0};
    int i = 0;
    if (c)
        i = 7;
    else
        i = 8;
    return buf[i]; /* Expect: here */
}
