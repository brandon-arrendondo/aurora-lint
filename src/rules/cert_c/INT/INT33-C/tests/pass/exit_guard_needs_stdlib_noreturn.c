/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS under the default and strict presets; VIOLATION under pedantic
 * Expect: default=clean strict=clean pedantic=violation
 *
 * The zero divisor leaves through exit(), which never returns in a hosted
 * environment (C11 7.22.4.4), so the division is guarded. The pedantic
 * preset trusts only a declared library, and this fixture declares none
 * (stdlib_noreturn), so the exit() branch may fall through to it.
 */
#include <stdlib.h>

int divide(int a, int b)
{
    if (b == 0) {
        exit(1);
    }
    return a / b;
}
