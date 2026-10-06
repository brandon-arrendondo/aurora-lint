/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * `get`'s only call site in the scanned source passes the address of an
 * object, but `get` has external linkage, so callers outside the scan can
 * pass anything (ADR-0011). The later test says `q` can be NULL, and an
 * open caller set proves nothing against it, so `q->a` is the first
 * unguarded dereference. The static counterpart passes.
 */
struct s { int a; };

int get(struct s *q) {
    int v = q->a;
    if (q == 0)
        return -1;
    return v;
}

int caller(void) {
    struct s local = { 1 };
    return get(&local);
}
