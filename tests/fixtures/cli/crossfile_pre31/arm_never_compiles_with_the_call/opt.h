#ifndef OPT_H
#define OPT_H

/* A build without option lookups makes the lookup a null constant, which
 * drops its argument; every other build calls the function. */
#ifdef OMIT_GET
#define get_opt(X) ((void *)0)
#else
void *get_opt_fn(int);
#define get_opt(X) get_opt_fn(X)
#endif

#endif
