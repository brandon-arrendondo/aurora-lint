/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * The test is of a different value: `q` is reassigned between the
 * dereference and the test, and the new value is never dereferenced.
 */
struct s { int a; struct s *next; };

int walk(struct s *q) {
    int v = q->a;
    q = q->next;
    if (q == 0)
        return v;
    return v + 1;
}
