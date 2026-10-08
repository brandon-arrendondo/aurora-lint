/*
 * Rule: MEM31-C
 * Source: regression
 * Status: PASS - memset(&p, ...) before the store changes nothing the loop frees
 *
 * The array is zeroed through its address first; the store and the count
 * come after it.
 */
#include <stdlib.h>
#include <string.h>
void reset(void);
void clear_all(char **v);
void keep(char ***v);
void free_all(char *(*v)[16]);
char **gsave;

int f(void){ char *p[16]; unsigned i, n = 0;
 memset(&p, 0, sizeof p); p[n] = malloc(8); n++;
 for (i = 0; i < n; i++) free(p[i]); return 0; }
