/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * BAIL_IF_EMPTY is an object-like macro that returns OK with `*pp` still
 * NULL. A statement that is only a name does nothing unless it is such a
 * macro, so OK proves nothing about `p`.
 */
#define OK 0
#define BAIL_IF_EMPTY if (s[0] == 0) return OK

static int g;

int get(const char *s, int **pp) {
    *pp = 0;
    BAIL_IF_EMPTY;
    *pp = &g;
    return OK;
}

int use(const char *s) {
    int *p;
    if (get(s, &p) == OK)
        return *p;
    return -1;
}
