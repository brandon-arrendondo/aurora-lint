/*
 * Rule: FLP02-C
 * Source: regression
 * Status: PASS - `*a->rows == *b->rows` compares two `double *`
 *
 * `rows` is a `double **`, so one dereference leaves a pointer, not a
 * double: the comparison is between two row pointers.
 */

struct mat {
    double **rows;
};

int same_row(struct mat *a, struct mat *b)
{
    return *a->rows == *b->rows;
}
