/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: the #else arm locks, but the #ifdef A arm locks only under an inner #ifdef B whose #else just logs, so the A && !B build stores the secret unlocked.
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
#ifdef A
#ifdef B
    mlock(key, 128);
#else
    puts("no lock");
#endif
#else
    mlock(key, 128);
#endif
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
