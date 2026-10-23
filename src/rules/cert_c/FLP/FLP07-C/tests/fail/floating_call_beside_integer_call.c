/*
 * Rule: FLP07-C
 * Source: aurora-lint
 * Status: FAIL - a float return assigned to a long double uncast
 *
 * ratio() is declared to return float, and its result may carry more range
 * or precision than float. The strlen() result beside it is an integer and
 * not the finding.
 */
#include <string.h>

float ratio(float a);

void measure(const char *s) {
    long double n = strlen(s);
    long double r = ratio(2.0f);
    (void)n;
    (void)r;
}
