/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The zero branch's break leaves only its own switch
 *
 * The `break` ends the `switch` inside the branch, so control continues
 * past the guard to the division when b is zero.
 */

int divide(int a, int b, int m)
{
    if (b == 0) {
        switch (m) {
        case 1:
            break;
        }
    }
    return a / b;
}
