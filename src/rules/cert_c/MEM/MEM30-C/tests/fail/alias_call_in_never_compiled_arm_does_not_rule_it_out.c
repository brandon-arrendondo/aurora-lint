/*
 * Rule: MEM30-C
 * Source: custom
 * Status: FAIL - Should trigger MEM30-C violation
 * Description: A call inside #if 0 is never compiled, so its argument count
 * says nothing about which XFREE is in force. The live calls pass one
 * argument, which free() takes, so XFREE is free() and the second release
 * is a double free.
 */

#include <stdlib.h>

#define XFREE free

void release(size_t n)
{
	char *p = malloc(n);

	if (p == NULL)
		return;
#if 0
	XFREE(p, NULL, 0);
#endif
	XFREE(p);
	XFREE(p);
}
