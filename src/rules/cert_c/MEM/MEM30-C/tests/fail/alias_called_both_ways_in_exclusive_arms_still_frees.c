/*
 * Rule: MEM30-C
 * Source: custom
 * Status: FAIL - Should trigger MEM30-C violation
 * Description: An alias is ruled out by argument count only when none of
 * the file's calls could compile with its target. Here one #ifdef arm calls
 * XFREE with three arguments and the other with one; the one-argument arm
 * is the build where XFREE is free(), and in that build the second release
 * is a double free.
 */

#include <stdlib.h>

#ifdef USE_POOL
void pool_free(void *p, void *heap, int type);
#define XFREE(p, h, t) pool_free((p), (h), (t))
#else
#define XFREE free
#endif

void release(size_t n)
{
	char *p = malloc(n);

	if (p == NULL)
		return;
#ifdef USE_POOL
	XFREE(p, NULL, 0);
#else
	XFREE(p);
	XFREE(p);
#endif
}
