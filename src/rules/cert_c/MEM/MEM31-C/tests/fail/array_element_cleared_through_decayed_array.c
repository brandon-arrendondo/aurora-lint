/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - memset(p, 0, sizeof p) clears every element after the store
 *
 * The array decays to a pointer a library call writes through.
 */
#include <stdlib.h>
#include <string.h>
void reset(void);
void clear_all(char **v);
void keep(char ***v);
void free_all(char *(*v)[16]);
char **gsave;

int f(void){ char *p[16]; unsigned i, n = 0;
 p[n] = malloc(8); n++; memset(p, 0, sizeof p);
 for (i = 0; i < n; i++) free(p[i]); return 0; }
