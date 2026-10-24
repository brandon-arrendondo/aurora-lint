/*
 * Rule: EXP35-C
 * Source: aurora-lint
 * Status: PASS - members of a temporary read by value, not an array member
 *
 * make().n is a scalar member, and make().a[1] and make().m[1][2] are each
 * the value of one element: none of them keeps a pointer into the
 * temporary, including when passed as a call's argument, since the value
 * is copied before the call.
 */
struct S { int n; int a[4]; int m[2][3]; };

struct S make(void) {
    struct S s = { 1, { 2, 3, 4, 5 }, { { 0 } } };
    return s;
}

int use(int v);

int read_members(void) {
    int n = make().n;
    int e = make().a[1];
    n = make().n;
    return use(make().n) + n + e;
}

int read_element_in_call(void) {
    return use(make().a[2]);
}

int read_element_of_row(void) {
    return use(make().m[1][2]) + make().m[0][1];
}
