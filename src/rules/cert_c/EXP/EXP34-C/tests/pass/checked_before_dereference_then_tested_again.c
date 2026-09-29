/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * `q` is tested and the NULL branch leaves before the first dereference, so
 * the later test is redundant, not evidence that the dereference was
 * unguarded.
 */
struct s { int a; };
void use(int v);

int get(struct s *q) {
    if (!q)
        return -1;
    int v = q->a;
    if (q != 0)
        use(v);
    return v;
}
