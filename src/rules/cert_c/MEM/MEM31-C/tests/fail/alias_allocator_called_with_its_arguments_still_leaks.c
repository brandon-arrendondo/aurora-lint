/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: The control for the pass/ fixture that rules an alias out
 * by its argument count. XMALLOC is malloc() in one build and is called
 * with the one argument malloc() takes, so the block it returns is an
 * allocation, and returning without releasing it leaks.
 */

#include <stdlib.h>

#ifdef USE_POOL
void *pool_malloc(size_t n);
#define XMALLOC(n) pool_malloc(n)
#else
#define XMALLOC malloc
#endif

int fill(size_t n)
{
	char *p = XMALLOC(n);

	if (p == NULL)
		return -1;
	p[0] = 1;
	return 0;
}
