/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: PASS - A macro that casts to a pointer typedef writes nothing
 *
 * `TOIP` expands to a cast to the pointer typedef `ip`, not a call, so
 * `gs` is still 3.
 */

typedef int *ip;

#define TOIP(x) ((ip)(x))

int gs;

int mask(int *a)
{
    gs = 3;
    int *y = TOIP(a);
    return (1 << gs) + *y;
}
