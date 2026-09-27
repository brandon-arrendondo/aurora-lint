/*
 * Rule: PRE00-C
 * Source: testcases
 * Status: FAIL - Should trigger PRE00-C violation
 *
 * The comment is white space: the body evaluates x twice, which an inline
 * function would not.
 */

#define SQUARE(x) ((x) * /* times itself */ (x)) /* VIOLATION */

int square(int i)
{
    return SQUARE(i);
}
