/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: A wrapper that returns sodium_malloc(n) directly hands back locked memory.
 */
#include <sys/mman.h>
#include <sys/resource.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
void *sodium_malloc(size_t);
static char *secure_alloc(size_t n) { return sodium_malloc(n); }
void h(const char *typed, const char *salt) {
    char *key = secure_alloc(128);
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
