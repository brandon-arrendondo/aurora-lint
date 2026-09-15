/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: PASS
 * Reason: A cleanup label at the end of one preprocessor arm falls through
 * to the statement after the #endif, not into the next arm and not off the
 * end of the function. The frees below the #endif are on every goto's path,
 * so nothing jumping to the label leaks what they release.
 */

#include <stdlib.h>

int setup(void *p);

int label_cleanup_continues_past_endif(void)
{
	int ret = -1;
	void *shared = malloc(16);
	if (!shared)
		return -1;
#ifdef VARIANT_A
	void *a = malloc(8);
	if (!a)
		goto out;
	if (setup(a) != 0)
		goto out;
	ret = 0;
out:
	free(a);
#else
	void *b = malloc(8);
	if (!b)
		goto out;
	if (setup(b) != 0)
		goto out;
	ret = 0;
out:
	free(b);
#endif
	free(shared);
	return ret;
}

/* A single-arm `#ifdef` FOLLOWING the label is a statement control enters,
 * not the end of an arm: the free inside it is on the goto's path. */
int label_cleanup_enters_following_ifdef(void)
{
	int ret = -1;
	void *a = malloc(8);
	void *b = malloc(8);
	if (!a || !b)
		goto out;
	if (setup(a) != 0)
		goto out;
	ret = 0;
out:
	free(a);
#ifdef VARIANT_A
	free(b);
#else
	free(b);
#endif
	return ret;
}
