/*
 * Rule: PRE31-C
 * Source: testcases
 * Status: PASS under the default preset; VIOLATION under strict
 * Expect: default=clean strict=violation
 *
 * strlen, strcmp and strncmp only read their arguments, and the
 * stdlib_call_effects contract lists them as free of side effects, so the
 * default policy treats a call to them as pure and re-evaluating it under a
 * double-evaluating macro changes nothing (pre31_listed_library_calls_pure).
 * The strict policy does not: CERT PRE31-C-EX1 counts "even changing errno"
 * as a side effect, and C11 7.5p3 lets any library function set errno unless
 * its description says otherwise, so each call is an unproven one, which
 * strict reports.
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
