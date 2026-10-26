/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: the call compiles in every configuration, including the one
 * where OMIT_GET is defined and the macro drops its argument.
 */

#ifdef OMIT_GET
#define get_opt(X) ((void *)0)
#else
void *get_opt_fn(int);
#define get_opt(X) get_opt_fn(X)
#endif

void g(void) {
    int i = 0;
    get_opt(i++);  // VIOLATION
    (void)i;
}
