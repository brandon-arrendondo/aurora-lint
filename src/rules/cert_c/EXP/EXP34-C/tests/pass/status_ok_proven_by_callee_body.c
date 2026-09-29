/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * prepare()'s own body stores a pointer it has proven non-null on every
 * path that returns OK. It returns NOMEM on the path that leaves `*pp`
 * NULL. So `p` is non-null wherever the status is known to be OK, whether
 * under an enclosing test or after an earlier test that returns.
 */
#include <stdlib.h>

#define OK 0
#define NOMEM 7

struct stmt { int n; };

int prepare(const char *sql, struct stmt **pp) {
    struct stmt *s;
    *pp = 0;
    s = malloc(sizeof *s);
    if (s == NULL)
        return NOMEM;
    s->n = sql[0];
    *pp = s;
    return OK;
}

int under_enclosing_test(const char *sql) {
    struct stmt *p = 0;
    int rc = prepare(sql, &p);
    if (rc == OK) {
        return p->n;
    }
    return -1;
}

int after_test_that_returns(const char *sql) {
    struct stmt *p = 0;
    int rc;
    rc = prepare(sql, &p);
    if (rc != OK)
        return rc;
    return p->n;
}
