/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: A project function that mlock()s its argument locks the caller's buffer.
 */

#include <sys/mman.h>
#include <crypt.h>
#include <stdlib.h>

static int pin_pages(void *p, size_t n) {
    return mlock(p, n);
}

void hash_key(const char *salt) {
    char *key = (char *)malloc(128);
    if (key == NULL) return;
    if (pin_pages(key, 128) != 0) {
        free(key);
        return;
    }
    crypt(key, salt);
    free(key);
}
