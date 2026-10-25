/*
 * Rule: EXP35-C
 * Source: aurora-lint
 * Status: PASS - ++, -- and & near a temporary, not on its array member
 *
 * The element make().a[0] is read as an index; &make().a[1] is used inside
 * its own C11 full expression; the array member reaches & only as a call's
 * argument; and the incremented and addressed objects are locals.
 */
#if __STDC_VERSION__ < 201112L
#error C11 or newer
#endif

struct S { int a[4]; int m[2][3]; };

struct S make(void) {
    struct S s = { { 1, 2, 3, 4 }, { { 0 } } };
    return s;
}

int use(int v);
int *first(int *a);
int read_ptr(const int *p);

int index_and_local(int *x) {
    struct S local = make();
    int *p = &local.a[0];
    ++local.a[1];
    ++x[make().a[0]];
    x[make().a[1]]--;
    return *p + read_ptr(&make().a[1]) + *&x[use(make().a[2])];
}

int *through_call(int *x) {
    int *q = &x[*first(make().a)];
    return q;
}
