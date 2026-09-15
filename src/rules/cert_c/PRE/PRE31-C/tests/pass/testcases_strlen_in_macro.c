/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger PRE31-C violation
 */

/*
 * Rule: PRE31-C - Avoid side effects in arguments to unsafe macros
 * Status: PASS
 * Reason: strlen/strcmp/strncmp only read their arguments and have no
 * observable side effects (PRE31-C-EX1) — re-evaluating them under a
 * double-evaluating macro changes nothing. (Previously misclassified as
 * side-effecting via errno; the C standard does not require strlen to set
 * errno, so this was a rule bug, not a real finding.)
 */

#include <string.h>

#define MAX(a, b) ((a) > (b) ? (a) : (b))  /* double-evaluates its args */

void string_compare(const char *s1, const char *s2) {
    size_t max_len = MAX(strlen(s1), strlen(s2));
    int c = MAX(strcmp(s1, s2), 0);
    int n = MAX(strncmp(s1, s2, 3), 0);
}

int main(void) {
    string_compare("hello", "world");
    return 0;
}
