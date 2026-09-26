/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: Juliet CWE-591 variant 41/51 shape: the caller allocates the password and hands it to a function that passes it to crypt(). Reported at the call, since the caller never frees it.
 */

#include <crypt.h>
#include <stdlib.h>
#include <string.h>

static const char *check_password(char *pw, const char *salt) {
    return crypt(pw, salt);
}

void authenticate(const char *typed, const char *salt) {
    char *pw = strdup(typed);
    if (pw == NULL) return;
    check_password(pw, salt);
}
