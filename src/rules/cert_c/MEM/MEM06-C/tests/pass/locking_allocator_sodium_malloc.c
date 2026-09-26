/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: sodium_malloc returns guarded, mlock()ed memory: the block is locked by construction.
 */

#include <sodium.h>
#include <string.h>

int hash_password(char *out, const char *typed) {
    char *pw = sodium_malloc(128);
    int rc;
    if (pw == NULL) return -1;
    strncpy(pw, typed, 127);
    pw[127] = 0;
    rc = crypto_pwhash_str(out, pw, strlen(pw), 2, 67108864);
    sodium_free(pw);
    return rc;
}
