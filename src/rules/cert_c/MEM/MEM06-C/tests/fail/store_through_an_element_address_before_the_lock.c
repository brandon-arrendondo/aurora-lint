/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: The secret is copied in through &key[0] before the lock.
 */
#include <sys/mman.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
void hash_key(const char *typed, const char *salt) {
    char *key = malloc(128);
    if (key == NULL) return;
    strcpy(&key[0], typed);
    mlock(key, 128);
    crypt(key, salt);
    free(key);
}
