/*
 * Rule: EXP35-C
 * Source: aurora-lint
 * Status: FAIL - the address of a temporary's array member returned
 *
 * &make().a points into the temporary, which ends with the return's
 * full expression.
 */
struct S { int a[4]; int m[2][3]; };

struct S make(void) {
    struct S s = { { 1, 2, 3, 4 }, { { 0 } } };
    return s;
}

int (*member(void))[4] {
    return &(make().a);
}
