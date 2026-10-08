/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - the loop frees only the element at index 7
 *
 * The free is under an if, so most iterations free nothing.
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
		if (i == 7)
			free(p[i]);
	return 0;
}
