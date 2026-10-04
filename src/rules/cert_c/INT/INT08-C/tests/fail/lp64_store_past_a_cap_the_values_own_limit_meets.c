/*
 * Rule: INT08-C
 * Source: regression
 * Status: FAIL - the model fixes every width, so no limit is open
 * Settings: data_model=lp64
 *
 * Under lp64 `v <= LLONG_MAX` is every value the type can hold, which says
 * nothing about a char destination, so the store truncates. The declaration
 * spelling (`long long`, a qualifier, a storage class) does not
 * change that: only the facts decide whether a limit is open.
 */

#include <limits.h>

void long_long_under_a_cap(void) {
    long long v = LLONG_MAX;
    if (v <= LLONG_MAX) {
        signed char c = v; /* VIOLATION */
        (void) c;
    }
}

void const_long_under_a_cap(void) {
    const long v = LONG_MAX;
    if (v <= LONG_MAX) {
        signed char c = v; /* VIOLATION */
        (void) c;
    }
}

void static_long_under_a_cap(void) {
    static long v = LONG_MAX;
    if (v <= LONG_MAX) {
        signed char c = v; /* VIOLATION */
        (void) c;
    }
}

void const_long_long_under_a_cap(void) {
    const long long v = LLONG_MAX;
    if (v <= LLONG_MAX) {
        signed char c = v; /* VIOLATION */
        (void) c;
    }
}
