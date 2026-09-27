/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: the Windows arm locks with VirtualLock, but the other arm's mlock sits under an inner #ifdef HAVE_MLOCK with no #else, so a non-Windows build without HAVE_MLOCK stores the secret unlocked.
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
#ifdef _WIN32
    VirtualLock(key, 128);
#else
#ifdef HAVE_MLOCK
    mlock(key, 128);
#endif
#endif
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
