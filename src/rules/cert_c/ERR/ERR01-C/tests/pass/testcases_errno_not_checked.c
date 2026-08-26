/*
 * Rule: ERR01-C
 * Source: testcases
 * Status: PASS - strtol/sqrt errno-checking is ERR30-C/ERR33-C's concern,
 * not ERR01-C's (which is specifically about FILE stream error checking via
 * ferror() vs errno). See ERR33-C's testcases_strtol_unchecked.c for the
 * equivalent fail case under the correct rule ID (task 592).
 */

#include <errno.h>
#include <math.h>
#include <stdlib.h>

/* strtol without errno check */
long parse_number(const char *str) {
    long result = strtol(str, NULL, 10);
    return result;
}

/* sqrt without errno check */
double safe_sqrt(double x) {
    double result = sqrt(x);
    return result;
}
