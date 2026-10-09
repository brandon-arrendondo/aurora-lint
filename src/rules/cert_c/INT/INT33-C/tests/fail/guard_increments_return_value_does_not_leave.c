/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The zero branch only updates a variable named like return
 *
 * `return_value++` spells "return" but is an expression statement, so the
 * division after the branch still runs when b is zero.
 */

int divide(int a, int b)
{
    int return_value = 0;
    if (b == 0) {
        return_value++;
    }
    return a / b + return_value;
}
