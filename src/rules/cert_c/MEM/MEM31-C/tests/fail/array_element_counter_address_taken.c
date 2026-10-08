/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - the loop hands &i to a callee that may advance it
 *
 * A write through the counter's address can skip elements unseen.
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
		free(p[i]);
		skip(&i);
	}
	return 0;
}
