/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - memcpy(p, other, sizeof p) overwrites the stored element
 *
 * The same with a copy into the array.
 */
#include <stdlib.h>
#include <string.h>
void reset(void);
void clear_all(char **v);
void keep(char ***v);
void free_all(char *(*v)[16]);
char **gsave;

int f(char **other){ char *p[16]; unsigned i, n = 0;
 p[n] = malloc(8); n++; memcpy(p, other, sizeof p);
 for (i = 0; i < n; i++) free(p[i]); return 0; }
