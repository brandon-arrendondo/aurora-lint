/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: A copy reaches crypt and is later reassigned from a parameter; the heap block it held is still judged.
 */
#include <crypt.h>
#include <stdlib.h>
#include <string.h>
void h(const char *typed, char *fallback) {
    char *t;
    char *pw = strdup(typed);
    if (!pw) return;
    t = pw;
    crypt(t, "ab");
    t = fallback;
    free(pw);
}
