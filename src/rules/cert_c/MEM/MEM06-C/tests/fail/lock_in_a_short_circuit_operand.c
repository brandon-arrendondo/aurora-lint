/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: the lock is the right operand of &&, so when `harden` is zero it never runs, yet the secret is stored and used either way.
 */

#include <crypt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

void h(const char *typed, const char *salt, int harden) {
    char *key = malloc(128);
    if (key == NULL) {
        return;
    }
    if (harden && mlock(key, 128) != 0) {
        free(key);
        return;
    }
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
