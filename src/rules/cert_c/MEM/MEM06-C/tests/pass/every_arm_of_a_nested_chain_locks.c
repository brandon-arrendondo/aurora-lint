/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: the #ifdef A arm holds an inner #ifdef B / #else that locks in both arms, and the outer #else locks too, so every configuration locks before the store.
 */

#include <crypt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

void h(const char *typed, const char *salt) {
    char *key = malloc(128);
    if (key == NULL) {
        return;
    }
#ifdef A
#ifdef B
    mlock(key, 128);
#else
    mlock(key, 128);
#endif
#else
    mlock(key, 128);
#endif
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
