/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * get() stores malloc()'s result only after testing it, and exits on the
 * path where it is NULL, so what the caller gets back in `p` is non-null.
 * The same holds when the test hands off to a project function this body
 * alone cannot tell is noreturn: the result was tested.
 */
#include <stdlib.h>

void fatal(const char *msg);

void get(char **pp) {
    char *s = malloc(10);
    if (s == NULL)
        exit(1);
    *pp = s;
}

void get_or_die(char **pp) {
    char *s = malloc(10);
    if (!s)
        fatal("out of memory");
    *pp = s;
}

void use(void) {
    char *p;
    char *q;
    get(&p);
    *p = 'a';
    free(p);
    get_or_die(&q);
    *q = 'b';
    free(q);
}
