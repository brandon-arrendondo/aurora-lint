/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * The fallback idiom: try one source, and if it produced nothing, try the
 * next. Every call is tracked as an allocation whether or not it returned
 * one, so the reassignment inside the `!p` guard used to re-file the first
 * "block" as leaked at `p@line:col` -- a block the guard proves never
 * existed. curl's lib/url.c detect_proxy reported six such leaks over one
 * chain of environment lookups, and create_conn_helper_init_proxy a
 * seventh. A NULL check joined by `&&` guards the same way: both conjuncts
 * hold in the true branch.
 */

#include <stdlib.h>
#include <string.h>

/* getenv-and-dup, as curl_getenv is: NULL when the name is unset. */
static char *lookup(const char *name) {
    const char *v = getenv(name);
    char *copy;
    if (!v) {
        return NULL;
    }
    copy = malloc(strlen(v) + 1);
    if (copy) {
        strcpy(copy, v);
    }
    return copy;
}
extern int prefer_upper(void);

void first_of_two(void) {
    char *p = lookup("http_proxy");
    if (!p) {
        p = lookup("HTTP_PROXY");
    }
    free(p);
}

void chain_of_four(void) {
    char *p = NULL;
    p = lookup("a");
    if (!p && prefer_upper()) {
        p = lookup("A");
    }
    if (p == NULL) {
        p = lookup("all");
        if (!p) {
            p = lookup("ALL");
        }
    }
    free(p);
}
