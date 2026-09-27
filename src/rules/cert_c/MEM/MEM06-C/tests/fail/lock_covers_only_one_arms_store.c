/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: one arm locks the block before storing the secret, the other arm stores it unlocked. The lock must precede every store, not just the textually first one.
 */

#include <crypt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

void h(const char *typed, const char *salt, int fast) {
    char *key = malloc(128);
    if (key == NULL) {
        return;
    }
    if (!fast) {
        mlock(key, 128);
        strcpy(key, typed);
    } else {
        strcpy(key, typed);
    }
    crypt(key, salt);
    free(key);
}
