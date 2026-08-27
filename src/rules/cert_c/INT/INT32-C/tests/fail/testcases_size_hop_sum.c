/*
 * Rule: INT32-C
 * Source: testcases
 * Status: FAIL - Should trigger INT32-C violation
 * Description: A multi-term strlen() sum assigned to a variable, then
 * passed to malloc() by that variable name one statement later (task
 * 604, modeled on pure-ftpd's log_pgsql.c query-buffer sizing).
 */

#include <stdlib.h>
#include <string.h>

char *build_query(const char *a, const char *b, const char *c,
                   const char *d, const char *e) {
    size_t total;
    char *buf;

    total = strlen(a) + strlen(b) + strlen(c) + strlen(d) + strlen(e);
    buf = malloc(total);
    return buf;
}
