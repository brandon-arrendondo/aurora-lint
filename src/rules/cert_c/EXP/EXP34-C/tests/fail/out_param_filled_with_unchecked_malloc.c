/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * get() always writes `*pp`, but what it writes is malloc()'s result,
 * which is NULL when the allocation fails. The write says the callee
 * stored something, not a usable pointer, so `p` may be NULL at `*p`.
 */
#include <stdlib.h>

void get(char **pp) {
    *pp = malloc(10);
}

void use(void) {
    char *p;
    get(&p);
    *p = 'a';
    free(p);
}
