/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The loop ends only when d is zero
 *
 * Control leaves `do ... while (d != 0)` when the condition is false, so d
 * is zero at the division.
 */

int divide(int a, int d)
{
    do {
        d--;
    } while (d != 0);
    return a / d;
}
