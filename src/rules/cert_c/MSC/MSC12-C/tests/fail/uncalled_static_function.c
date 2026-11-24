/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: FAIL - a static function nothing calls and whose address never escapes is never executed
 */
#include <stdio.h>

static void helper(void) /* Expect: here */
{
    puts("helper");
}

void api(void)
{
    puts("api");
}
