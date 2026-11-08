/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - An inner block on the same line does not size the outer array
 *
 * Both declarations share a line, so the line number does not tell them
 * apart. The access is outside the inner block.
 */

int element(void)
{
    char buf[8]; { char buf[4]; buf[0] = 1; } return buf[7];
}
