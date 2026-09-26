/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: `if (0 != mlock(...))` always evaluates the lock; only the right operand of && / || is conditional.
 */
#include <sys/mman.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
void hash_key(const char *typed, const char *salt) {
    char *key = malloc(128);
    if (key == NULL) return;
    if (0 != mlock(key, 128)) { free(key); return; }
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
