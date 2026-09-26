/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: The temporary is locked while it holds another buffer, then reassigned to the key: the key's pages were never locked.
 */
#include <sys/mman.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
static char scratch[64];
void hash_key(const char *typed, const char *salt) {
    char *t;
    char *key = malloc(128);
    if (key == NULL) return;
    t = scratch;
    mlock(t, 64);
    t = key;
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
