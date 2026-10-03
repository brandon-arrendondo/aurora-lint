/*
 * Rule: INT08-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * Without a declared model an end of the range can be the limit of a type
 * whose width is open, but nothing here compares the stored value against a
 * limit, so no guard can explain the open end away: `v > 1000` leaves
 * [1001, INT_MAX] and the smallest unsigned char holds 255, and a variable
 * at UINT_MAX or LONG_MAX is past it on every implementation.
 */

#include <limits.h>

void guarded_by_a_plain_bound(int v) {
    if (v > 1000) {
        unsigned char c = v; /* VIOLATION */
        (void) c;
    }
}

void unsigned_at_its_limit(void) {
    unsigned x = UINT_MAX;
    unsigned char c = x; /* VIOLATION */
    (void) c;
}

void long_at_its_limit(void) {
    long d = LONG_MAX;
    signed char r = d; /* VIOLATION */
    (void) r;
}
