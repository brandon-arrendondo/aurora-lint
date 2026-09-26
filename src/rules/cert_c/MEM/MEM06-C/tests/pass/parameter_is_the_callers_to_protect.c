/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: A buffer that arrives as a parameter is judged where it was allocated; this file allocates nothing.
 */

#include <crypt.h>
#include <stdlib.h>

void check_and_free(char *pw, const char *salt) {
    crypt(pw, salt);
    free(pw);
}
