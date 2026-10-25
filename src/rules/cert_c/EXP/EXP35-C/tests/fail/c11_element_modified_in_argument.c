/*
 * Rule: EXP35-C
 * Source: aurora-lint
 * Status: FAIL - a temporary's array element modified inside a C11 call argument
 *
 * Under C11 the temporary lives until the end of the full expression, so
 * reading or taking an address there is allowed; writing to it is not.
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

int bump(void) {
    return use(make().a[0]++);
}
