/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: PASS - A cast to a typedef name writes nothing
 *
 * `(u8x)(a)` is a cast, not a call, so `gs` is still 3.
 */

typedef unsigned char u8x;

int gs;

int mask(int a)
{
    gs = 3;
    int y = (u8x)(a);
    return (1 << gs) + y;
}
