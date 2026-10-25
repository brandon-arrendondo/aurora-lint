/*
 * Rule: EXP35-C
 * Source: aurora-lint
 * Status: FAIL - an element of a temporary's array member incremented
 *
 * ++make().a[0] writes to the temporary make() returned, outside any call
 * argument. tree-sitter-c parses ++x as an update_expression.
 */
struct S { int a[4]; int m[2][3]; };

struct S make(void) {
    struct S s = { { 1, 2, 3, 4 }, { { 0 } } };
    return s;
}

void bump(void) {
    ++make().a[0];
}
