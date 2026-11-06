/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: PASS - A macro that only evaluates its argument writes nothing
 *
 * `CHECK` expands to a cast of its argument, not a call, so `gs` is
 * still 3.
 */

#define CHECK(x) ((void)(x))

int gs;

int mask(void)
{
    gs = 3;
    CHECK(gs);
    return 1 << gs;
}
