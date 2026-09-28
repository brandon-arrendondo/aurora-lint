/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Expect: default=clean strict=violation
 * Reason: CALL_RUN calls through a member and CALL_PTR through a pointer, so
 * no body is named: the calls are unproven, which only the strict preset
 * reports.
 */

#define CALL_RUN(o) ((o)->vt->run(o))
#define CALL_PTR(fp, x) ((*(fp))(x))
#define TWICE(x) ((x) + (x))

struct obj;
struct vtable {
    int (*run)(struct obj *);
};
struct obj {
    const struct vtable *vt;
};

static int run_it(struct obj *o) {
    return CALL_RUN(o);
}

static int call_it(int (*fp)(int)) {
    return CALL_PTR(fp, 1);
}

int use_run(struct obj *o) {
    return TWICE(run_it(o));
}

int use_ptr(int (*fp)(int)) {
    return TWICE(call_it(fp));
}
