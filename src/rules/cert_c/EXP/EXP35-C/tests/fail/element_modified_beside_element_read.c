/*
 * Rule: EXP35-C
 * Source: aurora-lint
 * Status: FAIL - an element of a temporary's array member modified
 *
 * ++(make().a[0]) writes to the temporary make() returned. The element
 * read and passed by value on the line before it is not the finding.
 */
struct S { int a[4]; };

struct S make(void) {
    struct S s = { { 1, 2, 3, 4 } };
    return s;
}

int use(int v);

int bump(void) {
    int r = use(make().a[1]);
    return r + use(++(make().a[0]));
}
