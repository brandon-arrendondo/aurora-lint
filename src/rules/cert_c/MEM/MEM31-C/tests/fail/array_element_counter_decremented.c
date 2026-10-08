/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - n-- after the store moves the range away from it
 *
 * Decrementing is not counting: the loop's range no longer covers p[n].
 */
#include <stdlib.h>
void skip(unsigned *x);
int use(char **v, unsigned n);

int f(unsigned n0)
{
	char *p[16];
	unsigned i, n = n0;
	p[n] = malloc(8);
	n--;
	for (i = 0; i < n; i++)
		free(p[i]);
	return 0;
}
