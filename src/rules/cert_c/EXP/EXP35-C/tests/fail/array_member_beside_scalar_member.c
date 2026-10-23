/*
 * Rule: EXP35-C
 * Source: aurora-lint
 * Status: FAIL - a pointer to an array member of a temporary
 *
 * make().a decays to a pointer into the returned struct, which no longer
 * exists after the statement. make().n beside it is a value and not the
 * finding.
 */
struct S { int n; int a[4]; };

struct S make(void) {
    struct S s = { 1, { 2, 3, 4, 5 } };
    return s;
}

int keep(void) {
    int n = make().n;
    int *p = make().a;
    return n + p[0];
}
