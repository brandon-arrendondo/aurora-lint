/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: FAIL
 * Reason: Unlike a `goto`, a `break` leaves the branch but still reaches the
 * code after the loop, so a pointer freed before the `break` is freed on a
 * path that reaches the free below the loop. That is a double free.
 */

#include <stdlib.h>

int step(int i);

int free_before_break_then_free_after_loop(void)
{
	int i;
	void *p = malloc(8);
	if (!p)
		return -1;
	for (i = 0; i < 4; i++) {
		if (step(i)) {
			free(p);
			break;
		}
	}
	free(p);
	return 0;
}
