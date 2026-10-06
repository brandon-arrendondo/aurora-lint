/*
 * Rule: MEM30-C
 * Source: custom
 * Status: FAIL - Should trigger MEM30-C violation
 * Description: The control for the pass/ fixture that rules an alias out
 * by its argument count. Here one build makes XFREE the C library's free()
 * and the other a one-argument pool release, and the calls pass one
 * argument, which free() takes. The free() build compiles them, so the
 * second release is a double free in that build.
 */

#include <stdlib.h>

#ifdef USE_LIBC_ALLOCATOR
#define XFREE free
#else
void pool_free(void *p);
#define XFREE(p) pool_free(p)
#endif

void release_twice(size_t n)
{
	char *p = malloc(n);

	if (p == NULL)
		return;
	XFREE(p);
	XFREE(p);
}
