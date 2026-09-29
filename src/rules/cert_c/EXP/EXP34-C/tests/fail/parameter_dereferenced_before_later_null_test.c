/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * `q->a` is read before the function tests `q` for NULL. The test says `q`
 * can be NULL here, and no caller in the scanned source proves otherwise, so
 * the member access is the first unguarded dereference.
 */
struct s { int a; };

int get(struct s *q) {
    int v = q->a;
    if (q == 0)
        return -1;
    return v;
}
