/*
 * Rule: MEM30-C
 * Source: testcases (task 1360)
 * Status: FAIL - Should trigger MEM30-C violation
 *
 * The other half of modelling a loop's exits: a free on a path that
 * leaves the body by `break` or `continue`, or at the end of a body that
 * falls through, does reach the code after the loop. Before the loop
 * frame, an `if` arm ending in `break`/`continue` was read as leaving and
 * its free dropped -- the first two were recall gaps.
 */
#include <stdlib.h>

int cond(void);
void use(void *p);

void freed_on_the_break_path(void *p, int n)
{
	for (int i = 0; i < n; i++) {
		if (cond()) {
			free(p);
			break;
		}
	}
	use(p);
}

void freed_on_the_continue_path(void *p, int n)
{
	while (n--) {
		if (cond()) {
			free(p);
			continue;
		}
		use(p);
	}
	use(p);
}

void freed_at_the_end_of_the_body(void *p, int n)
{
	while (n--) {
		free(p);
	}
	use(p);
}
