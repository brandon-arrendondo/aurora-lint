/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - p[0] = NULL after the store drops the stored block
 *
 * Writing another element between the store and the freeing loop can
 * overwrite what the store put there.
 */
#include <stdlib.h>
#include <string.h>
void reset(void);
void clear_all(char **v);
void keep(char ***v);
void free_all(char *(*v)[16]);
char **gsave;

int f(void){ char *p[16]; unsigned i, n = 0;
 p[n] = malloc(8); n++; p[0] = NULL;
 for (i = 0; i < n; i++) free(p[i]); return 0; }
