/*
 * Rule: FLP07-C
 * Source: aurora-lint
 * Status: FAIL - a library function's double or float result assigned to a
 * long double uncast
 *
 * The headers are not expanded, so no prototype for atof(), strtod(),
 * floor(), ceilf() or modf() is in reach. The standard still fixes their
 * return types (double, or float for the f-suffixed form), and the names
 * are reserved to the library in every edition. modf() returns double:
 * its trailing f is part of its name.
 */
#include <math.h>
#include <stdlib.h>

void parse(const char *s, double d, float f) {
    double whole;
    long double a = atof(s);
    long double b;
    long double c = floor(d);
    long double e = ceilf(f);
    long double g = modf(d, &whole);
    b = strtod(s, NULL);
    (void)a;
    (void)b;
    (void)c;
    (void)e;
    (void)g;
}
