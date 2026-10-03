/*
 * Rule: INT32-C
 * Source: regression
 * Status: FAIL - the project declares plain char signed
 * Settings: data_model=lp64, char_signed=true
 *
 * No data model says whether plain char is signed, so CHAR_MAX is no number
 * until the project declares it. With char_signed = true and the preset's
 * 8-bit char it is 127, and adding one to it overflows the char it is
 * stored in.
 */

#include <limits.h>

char next_after_max(void) {
    char data = CHAR_MAX;
    char result = data + 1; /* VIOLATION */
    return result;
}
