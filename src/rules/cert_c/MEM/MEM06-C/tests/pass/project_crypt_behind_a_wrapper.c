/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: A project function named crypt, reached through a wrapper, is not the library call: the wrapper forwards to nothing that sinks a credential.
 */
#include <stdlib.h>
#include <string.h>
static size_t crypt(const char *text, const char *salt) { return strlen(salt) + strlen(text); }
static size_t wrap(char *text) { return crypt(text, "x"); }
size_t checksum(const char *typed) {
    char *copy = strdup(typed);
    size_t n;
    if (copy == NULL) return 0;
    n = wrap(copy);
    free(copy);
    return n;
}
