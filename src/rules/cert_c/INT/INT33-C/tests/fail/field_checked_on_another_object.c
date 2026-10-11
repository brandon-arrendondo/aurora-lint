/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - Only another object's denominator is checked
 *
 * check() tests g->denominator, in another function. Nothing tests the
 * denominator of the fraction divide() is given.
 */

struct fraction {
    int numerator;
    int denominator;
};

int check(const struct fraction *g)
{
    if (g->denominator == 0)
        return 0;
    return 1;
}

int divide(const struct fraction *f)
{
    return f->numerator / f->denominator;
}
