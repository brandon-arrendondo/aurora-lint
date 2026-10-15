/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should not trigger MEM31-C violation
 * Description: One declaration declares two locals, each a copy of its own
 * parameter, in either order, and the callee frees both. Each copy is found
 * apart from the other, so a call frees both of its arguments and neither
 * allocation leaks.
 */

#include <stdlib.h>

static void release_pair(char *p, char *q)
{
	char *a = p, *b = q;

	free(a);
	free(b);
}

static void release_pair_reversed(char *p, char *q)
{
	char *b = q, *a = p;

	free(b);
	free(a);
}

void no_leak(void)
{
	char *x = malloc(4);
	char *y = malloc(4);

	if (x == NULL || y == NULL) {
		free(x);
		free(y);
		return;
	}
	release_pair(x, y);
}

void no_leak_reversed(void)
{
	char *x = malloc(4);
	char *y = malloc(4);

	if (x == NULL || y == NULL) {
		free(x);
		free(y);
		return;
	}
	release_pair_reversed(x, y);
}
