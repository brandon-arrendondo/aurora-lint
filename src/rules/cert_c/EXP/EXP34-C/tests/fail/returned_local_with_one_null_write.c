/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * `slot` returns a local that one path leaves NULL, so the caller's
 * dereference before its test is unguarded.
 */
struct cell { int flags; };
struct vm { struct cell mem[8]; };

static struct cell *slot(struct vm *v, int i) {
    struct cell *out = &v->mem[0];
    if (i < 0 || i >= 8)
        out = 0;
    else
        out = &v->mem[i];
    return out;
}

int read_slot(struct vm *v, int i) {
    struct cell *c = slot(v, i);
    int flags = c->flags; // violation
    if (!c)
        return -1;
    return flags;
}
