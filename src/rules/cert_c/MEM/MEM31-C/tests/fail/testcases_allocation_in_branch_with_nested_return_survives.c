/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: FAIL
 * Reason: A branch that allocates and then only CONDITIONALLY returns still
 * allocated on the path that falls out of it. The block is never freed on
 * that path, so the function leaks it at its return. (A branch whose last
 * statement leaves is different -- see the pass fixture on label chains.)
 */

#include <stdlib.h>

int wanted(void);

int allocate_then_conditionally_return(void)
{
	void *p = NULL;
	if (wanted()) {
		p = malloc(16);
		if (!p)
			return -1;
	}
	return 0;
}
