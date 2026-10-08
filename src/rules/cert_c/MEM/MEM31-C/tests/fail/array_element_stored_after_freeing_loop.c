/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - the second store comes after the loop that freed the first
 *
 * The loop covers the store before it, never the one after it.
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
	for (i = 0; i < n; i++)
		free(p[i]);
	p[n] = malloc(8);
	n++;
	return 0;
}
