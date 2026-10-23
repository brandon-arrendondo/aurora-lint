/*
 * Rule: EXP35-C
 * Source: aurora-lint
 * Status: PASS - members of a temporary read by value, not an array member
 *
 * make().n is a scalar member and make().a[1] is the value of one element:
 * neither keeps a pointer into the temporary, including either one passed
 * as a call's argument: the value is copied before the call.
 */
struct S { int n; int a[4]; };

struct S make(void) {
    struct S s = { 1, { 2, 3, 4, 5 } };
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
