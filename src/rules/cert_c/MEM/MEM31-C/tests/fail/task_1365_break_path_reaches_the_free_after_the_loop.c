/*
 * Rule: MEM31-C
 * Source: testcases (task 1365)
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * The other half of modelling a loop's exits: a free on the path that
 * leaves the body by `break` does reach the free after the loop, so that
 * one is a double free on that path; and a body that ends by freeing
 * reaches the free after the loop when the condition fails on the next
 * test. Both were reported before this task and must stay reported now
 * that `break` leaves its branch.
 */
#include <stdlib.h>

int cond(void);

void freed_then_break_then_freed_again(int n)
{
	void *p = malloc(8);

	for (int i = 0; i < n; i++) {
		if (cond()) {
			free(p);
			break;
		}
	}
	free(p);
}

void body_end_frees_then_freed_again_after(int n)
{
	void *p = malloc(8);

	while (n--) {
		if (cond())
			break;
		free(p);
	}
	free(p);
}
