/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - the store goes through a pointer that aliases another array from its own declaration
 *
 * Only an array object's elements are credited. `p` names `buf`'s storage,
 * so clearing `buf[0]` drops the block `p[0]` held, and no occurrence of
 * `p` shows it.
 */
#include <stdlib.h>
#include <string.h>
int f(void){ char *buf[8]; char **p = buf; unsigned i, n = 0;
 p[n] = malloc(8); n++; buf[0] = NULL;
 for (i = 0; i < n; i++) free(p[i]); return 0; }
