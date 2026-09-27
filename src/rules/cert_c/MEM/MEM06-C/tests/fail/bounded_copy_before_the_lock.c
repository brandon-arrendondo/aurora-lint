/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: strcpy_s writes the secret into the block before mlock runs, so the lock comes too late. The Annex K bounded copy is a store like strcpy.
 */

#define __STDC_WANT_LIB_EXT1__ 1
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

void check(const char *typed, const char *salt) {
    char *key = malloc(128);
    if (key == NULL) {
        return;
    }
    strcpy_s(key, 128, typed);
    mlock(key, 128);
    crypt(key, salt);
    free(key);
}
