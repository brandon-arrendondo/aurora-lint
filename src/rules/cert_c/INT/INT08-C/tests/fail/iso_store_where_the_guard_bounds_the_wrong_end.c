/*
 * Rule: INT08-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * A limit guard explains an open range end away only when, on the branch the
 * store is in, it bounds the stored variable toward the destination: a cap
 * (`<=`, `<`) for an open top. The guards below put the value at or above the
 * limit, on the other branch of a cap, or in an `||` that does not hold, or
 * name another variable, so the store truncates whatever the limit is.
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

void floor_is_not_a_cap(void) {
    long v = LONG_MAX;
    if (v >= SCHAR_MAX) {
        signed char c = v; /* VIOLATION */
        (void) c;
    }
}

void floor_on_unsigned(unsigned long d) {
    d = ULONG_MAX;
    if (d >= UCHAR_MAX) {
        unsigned char r = d; /* VIOLATION */
        (void) r;
    }
}

void or_does_not_hold(unsigned long d, unsigned long y) {
    d = ULONG_MAX;
    if (d < 10 || y <= UCHAR_MAX) {
        unsigned char r = d; /* VIOLATION */
        (void) r;
    }
}

void limit_on_another_variable(unsigned long d, unsigned long y) {
    d = ULONG_MAX;
    if (y <= UCHAR_MAX) {
        unsigned char r = d; /* VIOLATION */
        (void) r;
    }
}
