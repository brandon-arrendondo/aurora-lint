/*
 * Rule: EXP34-C - Do not dereference null pointers
 * Status: FAIL - Should trigger EXP34-C violation
 * Reason: An assert's argument is compiled and evaluated in the debug
 *         configuration, so a null dereference inside it is a null
 *         dereference (ADR-0010 D5). malloc may return NULL, and the assert
 *         reads p->n before anything has checked p.
 */

#include <assert.h>
#include <stdlib.h>

struct item {
    int n;
};

int count_after_alloc(void) {
    struct item *p = malloc(sizeof(struct item));
    assert(p->n == 0);
    return 0;
}
