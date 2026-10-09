/*
 * Rule: MSC07-C
 * Source: synthetic
 * Status: VIOLATION under the default and strict presets; CLEAN under pedantic
 * Expect: default=violation strict=violation pedantic=clean
 *
 * exit() never returns in a hosted environment (C11 7.22.4.4), so the
 * statement after it is unreachable. The pedantic preset trusts only a
 * declared library, and this fixture declares none (stdlib_noreturn), so
 * exit() may return and the statement after it is reachable: the same
 * reading the control-flow rules take.
 */
#include <stdio.h>
#include <stdlib.h>

void fatal_error(void)
{
    exit(1);
    printf("unreachable\n");
}
