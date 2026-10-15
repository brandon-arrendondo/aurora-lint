/*
 * Rule: MEM30-C
 * Source: custom
 * Status: FAIL - Should trigger MEM30-C violation
 * Description: The same pair of copies declared the other way round: the
 * second parameter's copy comes first in the declaration. The call still
 * frees both arguments, and the write through the first after it is a use
 * after free.
 */

#include <stdlib.h>

static void release_pair(char *p, char *q)
{
	char *b = q, *a = p;

	free(b);
	free(a);
}

void use_after_release(void)
{
	char *x = malloc(4);
	char *y = malloc(4);

	if (x == NULL || y == NULL) {
		free(x);
		free(y);
		return;
	}
	release_pair(x, y);
	x[0] = 1;
}
