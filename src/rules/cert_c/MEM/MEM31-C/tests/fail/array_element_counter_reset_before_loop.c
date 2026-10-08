/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - n is reset to 0 before the loop
 *
 * n++ counts the store, then n = 0 empties the range the loop frees.
 */
#include <stdlib.h>
void skip(unsigned *x);
int use(char **v, unsigned n);

int f(unsigned n0)
{
	char *p[16];
	unsigned i, n = n0;
	p[n] = malloc(8);
	n++;
	n = 0;
	for (i = 0; i < n; i++)
		free(p[i]);
	return 0;
}
