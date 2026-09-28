/*
 * Rule: FLP02-C
 * Source: regression
 * Status: FAIL - `p->ratio == target` compares two doubles
 *
 * The left operand is a struct field declared double; it is typed by the
 * field's declaration.
 */

struct gauge {
    double ratio;
};

int at_target(const struct gauge *p, double target)
{
    return p->ratio == target;
}
