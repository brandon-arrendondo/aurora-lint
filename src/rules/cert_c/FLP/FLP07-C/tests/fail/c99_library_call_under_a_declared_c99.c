/*
 * Rule: FLP07-C
 * Source: aurora-lint
 * Status: FAIL - a C99 library function's double or float result assigned
 * to a long double uncast, under a declared C99
 * Settings: c_standard=c99
 *
 * The headers are not expanded, so no prototype for round(), cbrtf(),
 * expm1() or wcstod() is in reach. C99 added them and reserves their
 * names, so under a declared C99 the standard fixes their return types:
 * double, or float for the f-suffixed form. erf() returns double: its
 * trailing f is part of its name. fmal() already returns long double.
 */
#include <math.h>
#include <wchar.h>

void convert(const wchar_t *ws, double d, float f) {
    long double a = round(d);
    long double b = cbrtf(f);
    long double c = expm1(d);
    long double e = wcstod(ws, NULL);
    long double g = erf(d);
    long double h = fmal(d, d, d);
    (void)a;
    (void)b;
    (void)c;
    (void)e;
    (void)g;
    (void)h;
}
