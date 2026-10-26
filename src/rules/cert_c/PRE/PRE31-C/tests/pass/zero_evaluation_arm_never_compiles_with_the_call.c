/*
 * Rule: PRE31-C
 * Status: PASS - Should NOT trigger PRE31-C violation
 * Reason: the arm that drops its argument is defined only where OMIT_GET
 * is defined, and the call compiles only where it is not, so the call
 * always expands the arm that evaluates its argument once.
 */

#ifdef OMIT_GET
#define get_opt(X) ((void *)0)
#else
void *get_opt_fn(int);
#define get_opt(X) get_opt_fn(X)
#endif

void g(void) {
    int i = 0;
#ifndef OMIT_GET
    get_opt(i++);
#endif
    (void)i;
}
