/*
 * Rule: INT08-C
 * Source: regression
 * Status: FAIL - the value is past 255, and its top is not a number
 * Settings: data_model=lp64
 *
 * An unsigned long reaches 2^64 - 1, which the range engine's 64-bit signed
 * values cannot hold, so the end of this range is a clamp and the message
 * must say "at least 256" rather than print the clamp as an upper bound.
 */

#include <limits.h>

void else_of_a_cap(void) {
    unsigned long d = ULONG_MAX;
    if (d <= UCHAR_MAX) {
    } else {
        unsigned char r = d; /* VIOLATION */
        (void) r;
    }
}
