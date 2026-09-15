/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: FAIL
 * Reason: Handing the FIRST block held by `p` to the caller says nothing
 * about the second block allocated under the same name afterwards. That one
 * is never stored or freed, so it leaks at the return.
 */

#include <stdlib.h>

int second_block_under_escaped_name(void **out)
{
	void *p = calloc(1, 16);
	if (p == NULL)
		return -1;
	*out = p;
	p = calloc(1, 32);
	if (p == NULL)
		return -1;
	return 0;
}
