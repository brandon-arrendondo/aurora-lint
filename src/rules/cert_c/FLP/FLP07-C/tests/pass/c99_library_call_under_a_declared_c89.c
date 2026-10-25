/*
 * Rule: FLP07-C
 * Source: aurora-lint
 * Status: PASS - the file is declared C89, which leaves the C99 library
 * names to programs
 * Settings: c_standard=c89
 *
 * round(), cbrtf(), expm1() and wcstod() are functions C99 added under
 * names C90 did not reserve. Under a declared C89 a program may define its
 * own, so without a prototype in reach their return types are not known
 * and nothing is reported.
 */
#include <stddef.h>

void convert(const wchar_t *ws, double d, float f) {
    long double a = round(d);
    long double b = cbrtf(f);
    long double c = expm1(d);
    long double e = wcstod(ws, NULL);
    (void)a;
    (void)b;
    (void)c;
    (void)e;
}
