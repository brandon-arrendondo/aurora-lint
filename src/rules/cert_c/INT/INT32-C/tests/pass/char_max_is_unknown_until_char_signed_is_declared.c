/*
 * Rule: INT32-C
 * Source: regression
 * Status: PASS - nothing says whether plain char is signed
 * Settings: data_model=lp64
 *
 * Whether plain char is signed is implementation-defined and no preset
 * loads it, so CHAR_MAX is unknown and nothing here is proven to overflow.
 * Declaring char_signed makes it a number (see the fail fixture of the same
 * shape).
 */

#include <limits.h>

char next_after_max(void) {
    char data = CHAR_MAX;
    char result = data + 1;
    return result;
}
