/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - *(p + n) is a second store into p[n] before the count
 *
 * The second store is spelled through pointer arithmetic.
 */
#include <stdlib.h>
#include <string.h>
void reset(void);
void clear_all(char **v);
void keep(char ***v);
void free_all(char *(*v)[16]);
char **gsave;

int f(void){ char *p[16]; unsigned i, n = 0;
 p[n] = malloc(8); *(p+n) = malloc(8); n++;
 for (i = 0; i < n; i++) free(p[i]); return 0; }
