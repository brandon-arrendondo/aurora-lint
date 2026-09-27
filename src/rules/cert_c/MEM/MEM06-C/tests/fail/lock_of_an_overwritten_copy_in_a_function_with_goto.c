/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: q is copied from key and then pointed at another buffer before mlock(q), so the lock covers the spare buffer and not the secret. The function's goto must not keep the overwritten copy alive.
 */

#include <crypt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static char spare[128];

void h(const char *typed, const char *salt) {
    char *q;
    char *key = malloc(128);
    if (key == NULL) {
        goto out;
    }
    q = key;
    q = spare;
    mlock(q, 128);
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
out:
    return;
}
