/*
 * Rule: MEM31-C
 * Source: regression
 * Status: PASS - the body's own n is another object
 *
 * The loop body declares an unsigned n of its own. The bound i < n is still
 * the outer n, matched by declaration, so the store is covered.
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
		unsigned n = 1;
		free(p[i]);
	}
	return 0;
}
