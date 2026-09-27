/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: the #if 0 arm is never compiled, so the only live arm locks the block before the secret is stored.
 */

#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

void h(const char *typed, const char *salt) {
    char *key = malloc(128);
    if (key == NULL) {
        return;
    }
#if 0
    /* old path, kept for reference */
#else
    mlock(key, 128);
#endif
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
