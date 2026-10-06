/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: calloc() takes two arguments, so a two-argument call of an
 * alias whose target is calloc() fits it: the alias stays in force, the
 * call allocates, and returning without releasing the block leaks.
 */

#include <stdlib.h>

#define XCALLOC calloc

int fill(size_t n)
{
	char *p = XCALLOC(n, 1);

	if (p == NULL)
		return -1;
	p[0] = 1;
	return 0;
}
