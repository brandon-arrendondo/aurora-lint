/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: `*p++ = c` writes the secret through a copy of the pointer before mlock runs, so the lock comes too late.
 */

#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

void check(const char *salt) {
    char *key = malloc(128);
    if (key == NULL) {
        return;
    }
    char *p = key;
    int c;
    while ((c = getchar()) != EOF && c != '\n' && p < key + 127) {
        *p++ = (char)c;
    }
    mlock(key, 128);
    *p = '\0';
    crypt(key, salt);
    free(key);
}
