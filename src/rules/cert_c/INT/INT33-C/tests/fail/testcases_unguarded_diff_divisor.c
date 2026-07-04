/*
 * Rule: INT33-C
 * Source: testcases
 * Status: FAIL - Difference-of-bounds divisor with no ordering guard
 * Reason: mosquitto src/bridge.c:930 rand_between() — (high - low) is used as
 * a divisor with no guard that high > low; if a caller passes high <= low
 * this is a real divide-by-zero (or negative-modulo) bug.
 */

#include <stdlib.h>

static int rand_between(int low, int high) {
    int r;
    r = rand();
    return (abs(r) % (high - low)) + low;
}
