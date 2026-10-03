/*
 * Rule: INT08-C
 * Source: regression
 * Status: PASS - no data model is declared
 *
 * Without a declared data model the limit macros are only bounded from below
 * (UCHAR_MAX is at least 255, ULONG_MAX at least 4294967295) and the ranges do
 * not relate one macro to another. The guard `d <= UCHAR_MAX` is the
 * destination's own limit, so the store inside it fits whatever UCHAR_MAX is,
 * and a range with an open end is not a value the store can be judged by.
 */

#include <limits.h>

void narrow_after_the_guard(void) {
    unsigned long d = ULONG_MAX;
    if (d <= UCHAR_MAX) {
        unsigned char r = (unsigned char) d;
        (void) r;
    }
}

void narrow_signed_after_the_guard(void) {
    long d = LONG_MAX;
    if (d <= SCHAR_MAX) {
        signed char r = (signed char) d;
        (void) r;
    }
}
