/*
 * Rule: INT33-C
 * Source: synthetic
 * Status: FAIL - The field is assigned a value nobody checked
 */

struct range {
    int step;
};

int count(struct range *r, int lo, int hi, int step)
{
    r->step = step;
    return (hi - lo) / r->step;
}
