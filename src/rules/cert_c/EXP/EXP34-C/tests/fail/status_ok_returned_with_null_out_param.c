/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * prepare() returns OK for an empty statement with `*pp` still NULL, the
 * way sqlite3_prepare does, so testing for OK does not make `p` usable.
 */
#include <stdlib.h>

#define OK 0
#define NOMEM 7

struct stmt { int n; };

int prepare(const char *sql, struct stmt **pp) {
    struct stmt *s;
    *pp = 0;
    if (sql[0] == 0)
        return OK;
    s = malloc(sizeof *s);
    if (s == NULL)
        return NOMEM;
    s->n = 1;
    *pp = s;
    return OK;
}

int column_count(const char *sql) {
    struct stmt *p = 0;
    int rc = prepare(sql, &p);
    if (rc == OK) {
        return p->n;
    }
    return -1;
}
