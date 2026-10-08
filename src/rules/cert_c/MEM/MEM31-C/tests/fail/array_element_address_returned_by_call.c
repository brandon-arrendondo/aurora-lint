/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - id(&p) hands back an alias that clears p[0] after the store
 *
 * A callee handed the array's address may return or keep it; a write
 * through what it returned empties the element the loop would free.
 */
#include <stdlib.h>
#include <string.h>
void reset(void);
void clear_all(char **v);
void keep(char ***v);
void free_all(char *(*v)[16]);
char **gsave;

void *id(void *x); int f(void){ char *p[16]; char **q; unsigned i, n = 0;
 q = id(&p); p[n] = malloc(8); n++; q[0] = NULL;
 for (i = 0; i < n; i++) free(p[i]); return 0; }
