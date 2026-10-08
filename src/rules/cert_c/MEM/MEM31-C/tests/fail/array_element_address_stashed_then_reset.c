/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - stash(&p) may keep the address, and reset() may then clear p
 *
 * Only a zeroing call is trusted with the array's address.
 */
#include <stdlib.h>
#include <string.h>
void reset(void);
void clear_all(char **v);
void keep(char ***v);
void free_all(char *(*v)[16]);
char **gsave;

void stash(void *x); int f(void){ char *p[16]; unsigned i, n = 0;
 stash(&p); p[n] = malloc(8); n++; reset();
 for (i = 0; i < n; i++) free(p[i]); return 0; }
