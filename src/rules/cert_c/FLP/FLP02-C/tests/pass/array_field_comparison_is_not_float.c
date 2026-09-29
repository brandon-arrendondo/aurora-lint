/*
 * Rule: FLP02-C
 * Source: regression
 * Status: PASS - `a->v == b->v` compares two arrays' addresses
 *
 * The field is an array of double. Its type is not double: the comparison
 * is between the two arrays, each converted to a pointer to its first
 * element, and no floating-point value is compared.
 */

struct buf {
    double v[4];
};

int same_storage(struct buf *a, struct buf *b)
{
    return a->v == b->v;
}
