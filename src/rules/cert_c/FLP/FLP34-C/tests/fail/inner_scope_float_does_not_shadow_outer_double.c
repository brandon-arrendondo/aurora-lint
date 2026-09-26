/*
 * Rule: FLP34-C
 * Source: regression
 * Status: FAIL - `out = d` converts the outer double to float without a
 * range check
 *
 * An inner block declares its own `float d`. A function-wide name map keeps
 * one entry per name, and the inner declaration used to answer for the
 * outer `d`, so the assignment read as float to float. The occurrence's own
 * declaration is the outer double.
 */

void narrow_outer_double(void) {
    double d = 1e300;
    float out;
    out = d;
    {
        float d = 1.0f;
        (void)d;
    }
    (void)out;
}
