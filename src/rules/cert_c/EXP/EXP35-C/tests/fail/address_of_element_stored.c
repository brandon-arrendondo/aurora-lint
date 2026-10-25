/*
 * Rule: EXP35-C
 * Source: aurora-lint
 * Status: FAIL - the address of a temporary's array element stored
 *
 * p keeps &make().a[2] past the end of the full expression, where the
 * temporary's lifetime ends under C99 and C11 alike. tree-sitter-c parses
 * &x as a pointer_expression.
 */
#if __STDC_VERSION__ < 201112L
#error C11 or newer
#endif

struct S { int a[4]; int m[2][3]; };

struct S make(void) {
    struct S s = { { 1, 2, 3, 4 }, { { 0 } } };
    return s;
}

int *keep(void) {
    int *p = &make().a[2];
    return p;
}
