/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: both the #if A and the #elif B arm lock, but with neither macro defined no arm compiles and the secret is stored unlocked.
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
#if defined(A)
    mlock(key, 128);
#elif defined(B)
    mlock(key, 128);
#endif
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
