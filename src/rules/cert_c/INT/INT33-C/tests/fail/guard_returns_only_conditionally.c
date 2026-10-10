/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The zero branch returns only when v is set
 *
 * The return inside the zero branch is itself conditional. When b is zero
 * and v is zero, control falls out of the branch into the division. A guard
 * counts only when its branch always leaves.
 */

int divide(int a, int b, int v)
{
    if (b == 0) {
        if (v) return 0;
    }
    return a / b;
}
