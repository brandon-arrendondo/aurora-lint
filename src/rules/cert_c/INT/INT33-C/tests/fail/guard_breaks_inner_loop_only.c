/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The zero branch's break leaves only its own loop
 *
 * The `break` ends the `for (;;)` inside the branch, not the function, so
 * control continues past the guard to the division when b is zero.
 */

int divide(int a, int b)
{
    if (b == 0) {
        for (;;) {
            break;
        }
    }
    return a / b;
}
