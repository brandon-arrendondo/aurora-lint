/*
 * Rule: PRE02-C
 * Source: testcases
 * Status: PASS - Should not trigger PRE02-C violation
 *
 * The operators and parentheses these bodies hold sit inside string and
 * character literals, which are single tokens: none of them is an operator
 * the expansion could split from its operands.
 */

#include <stdio.h>

#define EXPRESSION "a + b * c"
#define HOME_URL "http://example.org/ - index"
#define OR_CLOSE_PAREN(x) ((x) | ')')

void show(int c)
{
    printf("%s %s %d\n", EXPRESSION, HOME_URL, OR_CLOSE_PAREN(c));
}
