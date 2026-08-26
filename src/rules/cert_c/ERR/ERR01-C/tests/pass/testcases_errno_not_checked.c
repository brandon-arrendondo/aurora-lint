/*
 * Rule: ERR01-C
 * Source: testcases
 * Status: FAIL - errno-setting functions called without errno check
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
