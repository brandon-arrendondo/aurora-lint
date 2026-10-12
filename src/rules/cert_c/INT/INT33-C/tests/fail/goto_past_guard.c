/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The guard's own goto lands before the division
 *
 * The guard leaves by jumping to a label that precedes the division, so
 * the division runs when the divisor is zero.
 */

int scaled(int a, int d)
{
    if (d == 0)
        goto out;
    a++;
out:
    return a / d;
}
