/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: PASS under the default and strict presets; VIOLATION under pedantic
 * Expect: default=clean strict=clean pedantic=violation
 *
 * A trailing exit() ends the function as surely as a return in a hosted
 * environment (C11 7.22.4.4). The pedantic preset trusts only a declared
 * library, and this fixture declares none (stdlib_noreturn), so nothing
 * says control cannot reach the closing brace.
 */
#include <stdlib.h>

int parse_or_die(int x)
{
    if (x) {
        return 1;
    }
    exit(1);
}
