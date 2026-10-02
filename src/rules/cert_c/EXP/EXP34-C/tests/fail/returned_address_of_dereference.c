/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * `&*q` is `q` itself (C11 6.5.3.2), not the address of an object, so
 * `same` returns whatever it was given, NULL included, and the caller's
 * dereference before its test is unguarded.
 */
struct cell { int flags; };

static struct cell *same(struct cell *q) {
    return &*q;
}

int read_cell(struct cell *in) {
    struct cell *c = same(in);
    int flags = c->flags; // violation
    if (!c)
        return -1;
    return flags;
}
