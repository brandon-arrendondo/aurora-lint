/*
 * Rule: INT08-C
 * Source: regression
 * Status: PASS - no data model is declared
 *
 * The cap holds on the branch the store is in, whether it is written as the
 * taken branch, the else of the opposite floor, or an exit before the store.
 */

#include <limits.h>

void else_of_a_floor(void) {
    unsigned long d = ULONG_MAX;
    if (d > UCHAR_MAX) {
    } else {
        unsigned char r = d;
        (void) r;
    }
}

void exit_before_the_store(void) {
    unsigned long d = ULONG_MAX;
    if (d > UCHAR_MAX) {
        return;
    }
    unsigned char r = d;
    (void) r;
}

void cap_in_a_conjunction(int ok) {
    long v = LONG_MAX;
    if (ok && v <= SCHAR_MAX) {
        signed char c = v;
        (void) c;
    }
}
