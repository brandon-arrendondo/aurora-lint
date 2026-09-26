/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: A memset with a non-zero fill stores data; it is not a clear, so the lock after it is too late.
 */
#include <sys/mman.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
void hash_key(int secret_byte, const char *salt) {
    char *key = malloc(128);
    if (key == NULL) return;
    memset(key, secret_byte, 127);
    key[127] = 0;
    mlock(key, 128);
    crypt(key, salt);
    free(key);
}
