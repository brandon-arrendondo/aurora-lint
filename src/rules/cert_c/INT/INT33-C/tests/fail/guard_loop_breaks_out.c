/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The zero branch's loop can end through its own break
 *
 * `while (1)` runs until ready is set, then the break leaves the loop and
 * control continues past the guard to the division with b still zero.
 */

int divide(int a, int b, volatile int ready)
{
    if (b == 0) {
        while (1) {
            if (ready)
                break;
        }
    }
    return a / b;
}
