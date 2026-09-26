/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: A project function that happens to be named crypt is not the library call; its summary says it sinks nothing.
 */

#include <stdlib.h>
#include <string.h>

static size_t crypt(const char *text, const char *salt) {
    return strlen(salt);
}

size_t checksum(const char *typed) {
    char *copy = strdup(typed);
    size_t n;
    if (copy == NULL) return 0;
    n = crypt("banner", copy);
    free(copy);
    return n;
}
