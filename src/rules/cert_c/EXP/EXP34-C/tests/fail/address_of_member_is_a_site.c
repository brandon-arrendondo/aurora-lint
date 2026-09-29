/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: FAIL - Should trigger EXP34-C violation
 *
 * Unlike `&*p` and `&p[i]`, `&p->a` evaluates the member access `(*p).a`,
 * so it dereferences a malloc() result nobody checked.
 */
#include <stdlib.h>

struct s { int a; };

int *member(void) {
    struct s *p = malloc(sizeof *p);
    return &p->a;
}
