/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: PASS under the default preset; VIOLATION under strict
 * Expect: default=clean strict=violation
 *
 * The zero divisor leaves through exit(), which never returns in a hosted
 * environment (C11 7.22.4.4), so the division is guarded. The strict
 * preset declares a freestanding environment with no library model
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
