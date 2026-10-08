/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - the loop hands &n to a callee that may change it
 *
 * A write through the bound's address can shrink the range unseen.
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
		skip(&n);
		free(p[i]);
	}
	return 0;
}
