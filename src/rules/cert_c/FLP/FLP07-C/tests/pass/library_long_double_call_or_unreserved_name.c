/*
 * Rule: FLP07-C
 * Source: aurora-lint
 * Status: PASS - no double or float library result reaches a long double
 * uncast
 *
 * strtold() and floorl() return long double, so their results need no
 * conversion. The atof() result is cast. round() and cbrt() are C99
 * additions under names C90 left to programs, so without a prototype in
 * reach their return types are not known and nothing is reported. The
 * file's own floor() returns int.
 */
#include <stdlib.h>

int floor(int x);

void parse(const char *s, long double x, double d) {
    long double a = strtold(s, NULL);
    long double b = floorl(x);
    long double c = (long double)atof(s);
    long double e = round(d);
    long double g = cbrt(d);
    long double h = floor(3);
    (void)a;
    (void)b;
    (void)c;
    (void)e;
    (void)g;
    (void)h;
}
