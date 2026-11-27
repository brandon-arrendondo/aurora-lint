/*
 * Rule: ARR00-C
 * Source: synthetic
 * Status: FAIL - A parameter of a function that returns a pointer indexes an array without a bounds check
 * Expect: count=2
 *
 * `slot` and `entry` return pointers, so their parameter lists sit under
 * pointer declarators. `i` is still their parameter, and nothing checks it
 * before it indexes the table.
 */
struct table {
    char names[8][16];
    int counts[8];
};

char *slot(struct table *t, int i)
{
    return t->names[i]; /* Expect: here */
}

int **entry(struct table *t, int i, int **out)
{
    *out = &t->counts[0];
    t->counts[i] = 1; /* Expect: here */
    return out;
}
