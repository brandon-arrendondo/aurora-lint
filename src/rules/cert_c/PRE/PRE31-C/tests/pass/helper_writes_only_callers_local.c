/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Expect: default=clean strict=violation
 * Reason: init writes through its pointer, but zero hands it the address of
 * zero's own local, so no write escapes zero. That is not proven impure: the
 * default preset stays silent and the strict preset reports it as unproven.
 */

#define TWICE(x) ((x) + (x))

static void init(int *p) {
    *p = 0;
}

int zero(void) {
    int v;
    init(&v);
    return v;
}

int use(void) {
    return TWICE(zero());
}
