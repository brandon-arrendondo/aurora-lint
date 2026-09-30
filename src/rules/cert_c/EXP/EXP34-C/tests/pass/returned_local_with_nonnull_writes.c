/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * `slot` returns a local whose only write is the address of an array
 * element, and `first_slot` returns `slot`'s result, so neither can return
 * NULL. Each caller's later test is redundant.
 */
struct cell { int flags; };
struct vm { struct cell mem[8]; };

static struct cell *slot(struct vm *v, int i) {
    struct cell *out;
    out = &v->mem[i];
    out->flags = 0;
    return out;
}

static struct cell *first_slot(struct vm *v) {
    return slot(v, 0);
}

int read_slot(struct vm *v, int i) {
    struct cell *c = slot(v, i);
    int flags = c->flags;
    if (!c)
        return -1;
    return flags;
}

int read_first(struct vm *v) {
    struct cell *f = first_slot(v);
    int flags = f->flags;
    if (!f)
        return -1;
    return flags;
}
