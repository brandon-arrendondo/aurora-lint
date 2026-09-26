/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: A secure allocator that returns NULL on failure and a locked block otherwise hands back locked memory.
 */
#include <sys/mman.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
static char *secure_alloc(size_t n) {
    char *p = malloc(n);
    if (p == NULL) return NULL;
    if (mlock(p, n) != 0) { free(p); return NULL; }
    return p;
}
void hash_key(const char *typed, const char *salt) {
    char *key = secure_alloc(128);
    if (key == NULL) return;
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
