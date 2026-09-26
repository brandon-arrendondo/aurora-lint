/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: The lock sits inside `if (key != NULL) { ... }` with the store and the sink: it runs before both on every path that stores the secret.
 */
#include <sys/mman.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
void hash_key(const char *typed, const char *salt) {
    char *key = malloc(128);
    if (key != NULL) {
        if (mlock(key, 128) != 0) { free(key); return; }
        strcpy(key, typed);
        crypt(key, salt);
        free(key);
    }
}
