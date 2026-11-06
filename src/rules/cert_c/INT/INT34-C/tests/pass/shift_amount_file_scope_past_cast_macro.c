/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: PASS - A macro that casts its argument writes nothing
 *
 * `LOW` expands to a cast to `uint8_t`, not a call, so `gs` is still 3.
 */

#include <stdint.h>

#define LOW(x) ((uint8_t)(x))

int gs;

int mask(int v)
{
    gs = 3;
    v = LOW(v);
    return (1 << gs) + v;
}
