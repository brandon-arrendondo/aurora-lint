/*
 * Rule: EXP35-C
 * Source: aurora-lint
 * Status: FAIL - a row of a temporary's two-dimensional array member
 *
 * make().m[1] is a row, int[3], which decays to a pointer into the struct
 * make() returned: passed to usep() or kept in r, it outlives the
 * temporary. make().m[1][2] beside it is one element, read by value, and
 * not the finding.
 */
struct S { int m[2][3]; };

struct S make(void) {
    struct S s = { { { 1, 2, 3 }, { 4, 5, 6 } } };
    return s;
}

int usep(const int *row);
int use(int v);

int rows(void) {
    int v = use(make().m[1][2]);
    int *r = make().m[1];
    return v + usep(make().m[0]) + r[0];
}
