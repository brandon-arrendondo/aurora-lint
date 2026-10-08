/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - a continue skips the free on most iterations
 *
 * The free is a statement of the body, but a continue before it skips it
 * unless i is 7.
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
	for (i = 0; i < n; i++) {
		if (i != 7)
			continue;
		free(p[i]);
	}
	return 0;
}
