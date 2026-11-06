/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: PASS - A comparison macro writes nothing
 *
 * `MIN` expands to a conditional expression, not a call, so `gs` is
 * still 3.
 */

#define MIN(a, b) ((a) < (b) ? (a) : (b))

int gs;

int mask(int v)
{
    gs = 3;
    v = MIN(v, 2);
    return (1 << gs) + v;
}
