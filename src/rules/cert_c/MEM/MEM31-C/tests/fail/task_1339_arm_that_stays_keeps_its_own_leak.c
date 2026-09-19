/*
 * Rule: MEM31-C
 * Source: testcases (task 1339)
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * Companion to the pass fixture that walks the else arm from the records
 * before the `if`: whichever arm reaches the code below the `if` still
 * owns what it allocated there, so a block made in the arm that stays --
 * true or else -- and never freed is reported, once at its declaration and
 * once at the return it is live at. And when both arms leave, an arm that
 * returns without freeing what the other arm freed is a leak on its path,
 * reported at that return.
 */
#include <stdlib.h>

int more(void);
void use(void *p);

int leak_in_the_else_arm(void)
{
	if (more()) {
		return 0;
	} else {
		void *q = malloc(8);

		use(q);
	}
	return 0;
}

int leak_in_the_true_arm(void)
{
	if (more()) {
		void *q = malloc(8);

		use(q);
	} else {
		return 0;
	}
	return 0;
}

int only_one_of_two_returning_arms_frees(void)
{
	void *p = malloc(8);

	if (!p)
		return -1;
	if (more()) {
		free(p);
		return 1;
	} else {
		return 0;
	}
}
