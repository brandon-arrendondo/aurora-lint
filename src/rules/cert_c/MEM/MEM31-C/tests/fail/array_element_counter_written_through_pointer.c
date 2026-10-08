/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - *q += 1 advances i through a pointer taken outside the loop
 *
 * The counter's address is taken in the function, so a write through q
 * reaches it although no statement names i.
 */
#include <stdlib.h>
void skip(unsigned *x);
int use(char **v, unsigned n);

int f(unsigned n0)
{
	char *p[16];
	unsigned i, n = n0;
	unsigned *q = &i;
	p[n] = malloc(8);
	n++;
	for (i = 0; i < n; i++) {
		free(p[i]);
		*q += 1;
	}
	return 0;
}
