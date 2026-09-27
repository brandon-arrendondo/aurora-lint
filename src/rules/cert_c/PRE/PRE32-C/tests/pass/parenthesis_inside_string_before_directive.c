/*
 * Rule: PRE32-C
 * Source: testcases
 * Status: PASS - Should not trigger PRE32-C violation
 *
 * The #ifdef group stands between two complete statements. The unmatched
 * parentheses before and after it are inside string literals and open or
 * close no call.
 */

#include <stdio.h>

void report(void)
{
    printf("(");
#ifdef VERBOSE
    printf("verbose");
#endif
    printf(")");
}
