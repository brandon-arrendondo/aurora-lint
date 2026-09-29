/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * `get` is static and its address never escapes, and its only call site
 * passes the address of an object, so `q` is proven non-null at entry. The
 * later test is redundant.
 */
struct s { int a; };

static int get(struct s *q) {
    int v = q->a;
    if (q == 0)
        return -1;
    return v;
}

int caller(void) {
    struct s local = { 1 };
    return get(&local);
}
