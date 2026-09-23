/*
 * Rule: MEM30-C
 * Source: testcases (task 1360)
 * Status: FAIL - Should trigger MEM30-C violation
 *
 * The limits of the equality-predicate record: the same test again, a
 * test on a value assigned in between, overlapping constant sets, names
 * that may be variables, two names for the same number, `!=` against a
 * different constant, a free that was unconditional on another path.
 * Each of these keeps the object freed on the arm that uses it.
 */
#include <stdlib.h>

#define A 1
#define B 2
#define ALSO_ONE 1
void use(void *p);

void same_test_again(int t, void *p)
{
	if (t == A)
		free(p);
	if (t == A)
		use(p);
}

void value_assigned_in_between(int t, void *p)
{
	if (t == A)
		free(p);
	t = B;
	if (t == B)
		use(p);
}

void overlapping_sets(int t, void *p)
{
	if (t == A)
		free(p);
	if (t == B || t == A)
		use(p);
}

void lower_case_names_may_be_variables(int t, int a, int b, void *p)
{
	if (t == a)
		free(p);
	if (t == b)
		use(p);
}

void two_names_for_one_number(int t, void *p)
{
	if (t == A)
		free(p);
	if (t == ALSO_ONE)
		use(p);
}

void not_equal_then_another_constant(int t, void *p)
{
	if (t != A)
		free(p);
	if (t == B)
		use(p);
}

void unconditional_on_another_path(int t, int x, void *p)
{
	if (x) {
		free(p);
	} else {
		if (t == A)
			free(p);
	}
	if (t == B)
		use(p);
}
