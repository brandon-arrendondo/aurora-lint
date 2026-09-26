/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: madvise(MADV_DONTDUMP) takes the buffer's address but writes nothing into it; the lock still runs before the first store.
 */
#include <sys/mman.h>
#include <sys/resource.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
void h(const char *typed, const char *salt) {
    char *key = malloc(128);
    if (!key) return;
    madvise(key, 128, MADV_DONTDUMP);
    if (mlock(key, 128) != 0) { free(key); return; }
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
