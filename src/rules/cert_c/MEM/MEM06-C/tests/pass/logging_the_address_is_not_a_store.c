/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: Printing the buffer's address with %p stores nothing in it; the lock runs before the secret is copied in.
 */
#include <sys/mman.h>
#include <sys/resource.h>
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
void h(const char *typed, const char *salt) {
    char *key = malloc(128);
    fprintf(stderr, "buf %p\n", (void*)key);
    if (mlock(key, 128) != 0) { free(key); return; }
    strcpy(key, typed);
    crypt(key, salt);
    free(key);
}
