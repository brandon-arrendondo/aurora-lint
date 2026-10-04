/*
 * Rule: INT08-C
 * Source: regression
 * Status: FAIL - the value is past 255, and its top is not a number
 * Settings: data_model=lp64
 *
 * A typedef name for an unsigned 64-bit type says nothing to the range
 * engine, and the type it names reaches 2^64 - 1, which the engine's 64-bit
 * signed values cannot hold. The top of the range is a clamp, so the message
 * must say "at least 256" however the parameter is spelled.
 */

#include <limits.h>

typedef unsigned long long wide_t;
typedef unsigned long counter_t;

void typedef_of_unsigned_long_long(wide_t p) {
    if (p <= UCHAR_MAX) {
    } else {
        unsigned char r = p; /* VIOLATION */
        (void) r;
    }
}

void typedef_of_unsigned_long(counter_t p) {
    if (p <= UCHAR_MAX) {
    } else {
        unsigned char r = p; /* VIOLATION */
        (void) r;
    }
}
