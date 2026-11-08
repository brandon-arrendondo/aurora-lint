/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - An inner block on the same line does not size the outer array
 * Expect: count=1
 *
 * Both declarations share a line. The access is outside the inner block,
 * so it names the four-element array.
 */

int element(void)
{
    char buf[4]; { char buf[8]; buf[0] = 1; } return buf[7];
}
