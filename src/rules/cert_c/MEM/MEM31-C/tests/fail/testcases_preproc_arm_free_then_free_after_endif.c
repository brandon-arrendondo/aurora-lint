/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: FAIL
 * Reason: A free inside one arm of an #ifdef/#else chain followed by a free
 * of the same pointer AFTER the #endif is a double free in the translation
 * unit that compiles that arm. Code below the chain coexists with every arm,
 * so making the arms exclusive of each other must not make them exclusive
 * of what follows.
 */

#include <stdlib.h>

int keygen(void);

int free_in_arm_then_free_after_chain(void)
{
	void *p = malloc(8);
	if (!p)
		return -1;
#ifdef VARIANT_A
	if (keygen() != 1)
		free(p);
#else
	keygen();
#endif
	free(p);
	return 0;
}

int free_before_chain_then_free_in_arm(void)
{
	void *q = malloc(8);
	if (!q)
		return -1;
	free(q);
#ifdef VARIANT_A
	keygen();
#else
	free(q);
#endif
	return 0;
}
