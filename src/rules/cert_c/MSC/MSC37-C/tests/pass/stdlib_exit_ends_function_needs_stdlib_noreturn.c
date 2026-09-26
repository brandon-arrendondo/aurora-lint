/*
 * Rule: MSC37-C
 * Source: synthetic
 * Status: PASS under the default preset; VIOLATION under strict
 * Expect: default=clean strict=violation
 *
 * A trailing exit() ends the function as surely as a return in a hosted
 * environment (C11 7.22.4.4). The strict preset declares a freestanding
 * environment with no library model (stdlib_noreturn), so nothing says
 * control cannot reach the closing brace.
 */
#include <stdlib.h>

int parse_or_die(int x)
{
    if (x) {
        return 1;
    }
    exit(1);
}
