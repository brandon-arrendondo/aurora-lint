/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: the Windows build locks the block with VirtualLock and every other build with mlock, both before the secret is stored, so every configuration is covered.
 */

#include <crypt.h>
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
#ifdef _WIN32
    VirtualLock(key, 128);
#else
    mlock(key, 128);
#endif
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
