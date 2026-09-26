/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: A password read into a local array reaches crypt(); the array's pages are never locked.
 */

#include <crypt.h>
#include <stdio.h>

const char *hash_typed(const char *salt) {
    char pw[128];
    if (fgets(pw, sizeof pw, stdin) == NULL) return NULL;
    return crypt(pw, salt);
}
