/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: A do { } while (0) body always runs once, so its lock precedes the store.
 */
#include <sys/mman.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
void hash_key(const char *typed, const char *salt) {
    char *key = malloc(128);
    if (key == NULL) return;
    do { if (mlock(key, 128)) { free(key); return; } } while (0);
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
