/*
 * Rule: CON35-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON35-C violation
 *
 * The callbacks are named mtx_lock, but they are parameters, not the C11
 * function (resolved by declaration): no mutex is acquired here.
 */

#include <threads.h>

struct pair {
    int a, b;
};

void swap_with(struct pair *p, void (*mtx_lock)(int *)) {
    mtx_lock(&p->a);
    mtx_lock(&p->b);
}
