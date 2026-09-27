/*
 * Rule: PRE12-C
 * Source: testcases
 * Status: FAIL - Should trigger PRE12-C violation
 *
 * The comment is white space: the body evaluates x twice, so SQUARE(i++)
 * increments i twice.
 */

#define SQUARE(x) ((x) * /* times itself */ (x)) /* VIOLATION */

int square(int i)
{
    return SQUARE(i);
}
