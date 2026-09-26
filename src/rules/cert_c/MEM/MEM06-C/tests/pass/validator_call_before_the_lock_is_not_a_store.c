/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: An unknown validator handed the buffer is not assumed to write through it; the lock runs before the strcpy.
 */
#include <sys/mman.h>
#include <sys/resource.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int valid(const void *p);
void h(const char *typed, const char *salt) {
    char *key = malloc(128);
    if (!valid(key)) return;
    mlock(key, 128);
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
