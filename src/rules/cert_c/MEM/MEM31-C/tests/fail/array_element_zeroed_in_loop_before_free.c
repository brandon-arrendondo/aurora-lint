/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - the loop zeroes p[i] through its address before freeing it
 *
 * memset(&p[i], ...) leaves the free with nothing to release.
 */
#include <stdlib.h>
#include <string.h>
void reset(void);
void clear_all(char **v);
void keep(char ***v);
void free_all(char *(*v)[16]);
char **gsave;

int f(void){ char *p[16]; unsigned i, n = 0;
 p[n] = malloc(8); n++;
 for (i = 0; i < n; i++) { memset(&p[i], 0, sizeof p[i]); free(p[i]); } return 0; }
