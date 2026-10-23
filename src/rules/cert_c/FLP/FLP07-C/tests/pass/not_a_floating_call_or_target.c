/*
 * Rule: FLP07-C
 * Source: aurora-lint
 * Status: PASS - no floating return reaches a long double
 *
 * strlen() returns size_t, not a floating type. total is a double, and the
 * long double t declared beside it is not the target: a name containing "t"
 * is not t. precise() returns long double, so its result reaches l with no
 * conversion.
 */
#include <string.h>

float ratio(float a);

void measure(const char *s) {
    long double n = strlen(s);
    long double t = 0;
    double total;
    total = ratio(2.0f);
    (void)n;
    (void)t;
    (void)total;
}

long double precise(long double x);

long double same_type(void) {
    long double l = precise(1.0L);
    return l;
}
