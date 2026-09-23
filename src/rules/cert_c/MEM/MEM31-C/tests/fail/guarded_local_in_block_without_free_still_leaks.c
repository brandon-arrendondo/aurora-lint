/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * The companion to the pass fixture: the same block-scoped local behind
 * the same `if (!p) return;` guard, with no free on the fall-through
 * path. Reading the branch as falling through must keep the
 * allocation it made on that path, so the leak is still reported at the
 * end of the function -- and a branch that frees, then returns only
 * SOMETIMES, did free on the path that falls out of it, so the free below
 * is a second one.
 */
#include <stdlib.h>

void use(void *p);

void guarded_never_freed(const char *ie, size_t len)
{
	if (ie) {
		void *p = malloc(len);

		if (!p)
			return;
		use(p);
	}
}

int freed_then_sometimes_returned(void *p, int x, int a)
{
	if (x) {
		free(p);
		if (a)
			return 1;
	}
	free(p);
	return 0;
}
