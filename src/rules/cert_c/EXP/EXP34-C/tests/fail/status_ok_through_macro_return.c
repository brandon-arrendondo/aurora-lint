/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * get() returns OK from inside RET_OK_IF() with `*pp` still NULL. The
 * macro's `return` is a path out of the body as real as a written one, so
 * OK proves nothing about `p`.
 */
#define OK 0
#define RET_OK_IF(c) if (c) return OK

static int g;

int get(int c, int **pp) {
    *pp = 0;
    RET_OK_IF(c);
    *pp = &g;
    return OK;
}

int use(int c) {
    int *p;
    if (get(c, &p) == OK)
        return *p;
    return -1;
}
