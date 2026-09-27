/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: the lock sits in one arm of ?:, so when `harden` is zero it never runs, yet the secret is stored and used either way.
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
    int rc = harden ? mlock(key, 128) : 0;
    (void)rc;
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
