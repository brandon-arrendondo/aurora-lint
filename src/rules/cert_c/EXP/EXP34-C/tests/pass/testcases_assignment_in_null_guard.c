/*
 * Rule: EXP34-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP34-C violation
 */

/*
 * Rule: EXP34-C - Do not dereference null pointers
 * Status: PASS
 * Reason: Each pointer is assigned inside its own null test, and the test
 *         leaves or skips the use when it is null. The value of `(p = e)` is
 *         the new `p`, so `if ((p = e) == NULL) return;` checks `p` exactly
 *         as `p = e; if (p == NULL) return;` does.
 *
 *         Distilled from valkey src/setproctitle.c
 *         (`if (!(base = argv[0])) return;`) and the ubiquitous
 *         `if ((p = malloc(n)) == NULL)` idiom.
 */

#include <stdlib.h>

struct obj {
    int x;
};

struct obj *lookup(void);

int eq_null_return(void)
{
    struct obj *p;
    if ((p = malloc(sizeof *p)) == NULL)
        return -1;
    p->x = 1;
    free(p);
    return 0;
}

int not_assign_return(void)
{
    struct obj *p;
    if (!(p = lookup()))
        return -1;
    return p->x;
}

int ne_null_use(void)
{
    struct obj *p;
    if ((p = lookup()) != NULL)
        return p->x;
    return 0;
}

int truthy_use(void)
{
    struct obj *p;
    if ((p = lookup()))
        return p->x;
    return 0;
}

int argv_base(char **argv)
{
    char *base;
    char *nul;
    if (!(base = argv[0]))
        return -1;
    nul = &base[1];
    return *nul;
}
