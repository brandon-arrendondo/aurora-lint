/*
 * Rule: PRE32-C
 * Source: testcases
 * Status: PASS - Should not trigger PRE32-C violation
 *
 * The directives are inside a string literal: no line of this call's
 * argument list begins with a #.
 */

#include <stdio.h>

void usage(void)
{
    printf("use #include <x.h> or #define Y\n");
}
