/*
 * Rule: FLP03-C
 * Source: regression
 * Status: FAIL - `p->total / n` is a floating-point division
 *
 * The dividend is a struct field declared double, typed by the field's
 * declaration, so dividing it by the zero `n` is a floating-point division.
 */

struct tally {
    double total;
};

double mean(const struct tally *p)
{
    int n = 0;
    return p->total / n;
}
