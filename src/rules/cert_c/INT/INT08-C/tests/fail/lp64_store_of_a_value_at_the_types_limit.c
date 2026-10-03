/*
 * Rule: INT08-C
 * Source: regression
 * Status: FAIL - the model fixes long and long long, so a value at their
 *         limit is a number, not an unknown
 * Settings: data_model=lp64
 *
 * LLONG_MAX is 9223372036854775807 under lp64, and so is a range end that
 * reaches it; neither is an open end, and storing either in a char truncates.
 */

#include <limits.h>

void llong_max_into_a_char(void) {
    long long d = LLONG_MAX;
    signed char r = d; /* VIOLATION */
    (void) r;
}

void long_min_into_a_short(void) {
    long d = LONG_MIN;
    short r = d; /* VIOLATION */
    (void) r;
}

void guarded_below_into_an_unsigned_char(long v) {
    if (v > 1000) {
        unsigned char c = v; /* VIOLATION */
        (void) c;
    }
}

void guarded_above_into_a_signed_char(long v) {
    if (v < -1000) {
        signed char c = v; /* VIOLATION */
        (void) c;
    }
}
