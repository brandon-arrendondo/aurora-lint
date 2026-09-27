/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: the #ifdef arm locks the block but the #else arm only logs, so that build stores and uses the secret unlocked.
 */

#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

void h(const char *typed, const char *salt) {
    char *key = malloc(128);
    if (key == NULL) {
        return;
    }
#ifdef HAVE_MLOCK
    mlock(key, 128);
#else
    puts("memory locking unavailable");
#endif
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
