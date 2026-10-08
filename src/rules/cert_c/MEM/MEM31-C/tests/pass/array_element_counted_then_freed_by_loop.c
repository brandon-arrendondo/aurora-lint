/*
 * Rule: MEM31-C
 * Source: regression
 * Status: PASS - p[n] is counted by n++ and the loop frees p[0..n-1]
 *
 * The minimal counted store: the one element stored is inside the loop's
 * range.
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
	return 0;
}
