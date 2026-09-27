/*
 * Rule: PRE02-C
 * Source: testcases
 * Status: PASS - Should not trigger PRE02-C violation
 *
 * Each replacement list is a single function call (EX1) or a single array
 * subscript (EX2). The operators sit inside the call's parentheses or the
 * subscript's brackets, so nothing around the expansion can split them.
 */

int table[16];
int combine(int a, int b);

#define COMBINED(a, b) combine((a) + 1, (b) * 2)
#define NEXT_SLOT(i) table[(i) + 1]

int use(int x, int y)
{
    return COMBINED(x, y) + NEXT_SLOT(x);
}
