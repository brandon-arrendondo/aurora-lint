/*
 * Rule: FLP06-C
 * Source: regression
 * Status: FAIL - `a / b` is integer division initializing a float
 *
 * An inner block declares its own `double a`. A function-wide name map keeps
 * one entry per name, and the inner declaration used to answer for the
 * outer `a`, so the division did not read as integer arithmetic. The
 * occurrence's own declaration is the outer int.
 */

float ratio(void) {
    int a = 7, b = 2;
    float r = a / b;
    {
        double a = 1.0;
        (void)a;
    }
    return r;
}
