/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: an indented, empty #if 0 arm is never compiled, so the #else arm's lock covers every build.
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
    #if 0
    #else
    mlock(key, 128);
    #endif
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
