/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - n is never incremented, so p[n] is outside i < n
 *
 * The store at p[n] with no n++ after it: the loop frees p[0..n-1] and
 * never reaches p[n].
 */
#include <stdlib.h>
void skip(unsigned *x);
int use(char **v, unsigned n);

int f(unsigned n0)
{
	char *p[16];
	unsigned i, n = n0;
	p[n] = malloc(8);
	for (i = 0; i < n; i++)
		free(p[i]);
	return 0;
}
