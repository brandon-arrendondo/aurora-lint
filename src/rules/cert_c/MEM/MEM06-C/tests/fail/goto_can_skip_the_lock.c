/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: A goto jumps past the lock to the store, so the lock does not run on every path.
 */
#include <sys/mman.h>
#include <sys/resource.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
void h(const char *typed, const char *salt, int fast) {
    char *key = malloc(128);
    if (fast) goto fill;
    mlock(key, 128);
fill:
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
