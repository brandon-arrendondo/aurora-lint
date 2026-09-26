/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: libsodium's sodium_mlock locks the pages before the password is stored.
 */
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
int h(char *out, const char *typed) {
    char *pw = malloc(128);
    int rc;
    if (!pw) return -1;
    if (sodium_mlock(pw, 128) != 0) { free(pw); return -1; }
    strncpy(pw, typed, 127);
    pw[127] = 0;
    rc = crypto_pwhash_str(out, pw, strlen(pw), 2, 67108864);
    sodium_munlock(pw, 128);
    free(pw);
    return rc;
}
