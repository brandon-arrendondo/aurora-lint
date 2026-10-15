/*
 * Rule: MEM30-C
 * Source: custom
 * Status: FAIL - Should trigger MEM30-C violation
 * Description: One declaration declares two locals, each a copy of its own
 * parameter, and the callee frees both. The second declarator's copy is
 * found apart from the first's, so the call frees its second argument too,
 * and the write through it after the call is a use after free.
 */

#include <stdlib.h>

static void release_pair(char *p, char *q)
{
	char *a = p, *b = q;

	free(a);
	free(b);
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
	y[0] = 1;
}
