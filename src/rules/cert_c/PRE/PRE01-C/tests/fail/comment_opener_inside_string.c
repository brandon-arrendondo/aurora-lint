/*
 * Rule: PRE01-C
 * Source: testcases
 * Status: FAIL - Should trigger PRE01-C violation
 *
 * The slash-star is inside a string literal and opens no comment, so the
 * list goes on to `p + 1`, where p is an unparenthesized operand:
 * SHOW_NEXT(a ? b : c) expands to `a ? b : c + 1`.
 */

#include <stdio.h>

#define SHOW_NEXT(p) printf("/* %d */\n", p + 1) /* VIOLATION */

void show(int v)
{
    SHOW_NEXT(v);
}
