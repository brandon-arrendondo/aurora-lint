/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * pick() returns 0 on both arms of its conditional, and one arm stores
 * NULL through `*pp`. A status of 0 therefore proves nothing about `p`,
 * which may be NULL when it is dereferenced.
 */
static int g;

int pick(int c, int **pp) {
    c ? (*pp = 0) : (*pp = &g);
    return 0;
}

int use(int c) {
    int *p = 0;
    int rc = pick(c, &p);
    if (rc == 0)
        return *p;
    return -1;
}
