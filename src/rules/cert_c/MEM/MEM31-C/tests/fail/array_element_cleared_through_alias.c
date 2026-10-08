/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - q = p aliases the array, and q[0] = NULL clears the stored element
 *
 * A decayed copy of the array writes its elements under another name.
 */
#include <stdlib.h>
#include <string.h>
void reset(void);
void clear_all(char **v);
void keep(char ***v);
void free_all(char *(*v)[16]);
char **gsave;

int f(void){ char *p[16]; char **q = p; unsigned i, n = 0;
 p[n] = malloc(8); n++; q[0] = NULL;
 for (i = 0; i < n; i++) free(p[i]); return 0; }
