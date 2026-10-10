/*
 * Rule: MSC07-C
 * Source: synthetic
 * Status: FAIL - Code after a parenthesized call to the library's exit()
 *
 * `(exit)(1)` still calls the standard library's exit(); the parentheses
 * only keep a function-like macro of that name from expanding. The
 * statement after it is unreachable.
 */
#include <stdio.h>
#include <stdlib.h>

void fatal_error(void)
{
    (exit)(1);
    printf("unreachable\n");
}
