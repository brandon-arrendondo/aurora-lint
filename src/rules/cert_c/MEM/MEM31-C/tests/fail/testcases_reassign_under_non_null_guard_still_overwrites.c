/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: Twin of tests/pass/
 * testcases_reassign_under_null_guard_is_not_overwrite.c. Only a guard that
 * proves the name NULL excuses the reassignment. Here the guard proves the
 * opposite -- `if (p)` enters only when the first block exists -- so the
 * second lookup overwrites a live pointer and the first block is leaked.
 * A guard on the other operand of `&&` says nothing about `p` either.
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

void overwrite_when_present(void) {
    char *p = lookup("http_proxy");
    if (p) {
        p = lookup("HTTP_PROXY");
    }
    free(p);
}

void guard_on_something_else(int flag) {
    char *p = lookup("a");
    if (!flag && prefer_upper()) {
        p = lookup("A");
    }
    free(p);
}
