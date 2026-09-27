/*
 * Rule: PRE12-C
 * Source: testcases
 * Status: PASS - Should not trigger PRE12-C violation
 *
 * Each parameter is evaluated once. Its other spellings are not
 * evaluations: inside a string literal or a comment, as the operand of #,
 * or inside sizeof.
 */

#include <stdio.h>

void fail(const char *expression);

#define SHOW(x) printf("x=%d\n", x)
#define CHECK(e) ((e) ? (void)0 : fail(#e))
#define SCALED(x) ((x) * sizeof(x)) /* x is read once */

int use(int v)
{
    SHOW(v);
    CHECK(v > 0);
    return (int)SCALED(v);
}
