/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * `current` returns the address of a static object on its only path, so its
 * body proves the result non-null. The later test is redundant.
 */
struct s { int a; };
static struct s the_one;

static struct s *current(void) {
    return &the_one;
}

int read_current(void) {
    struct s *p = current();
    int v = p->a;
    if (!p)
        return -1;
    return v;
}
