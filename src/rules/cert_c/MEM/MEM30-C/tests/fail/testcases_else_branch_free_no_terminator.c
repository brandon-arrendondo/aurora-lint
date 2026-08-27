/*
 * Rule: MEM30-C
 * Source: regression counterpart to testcases_free_in_else_branch_terminator.c
 * Status: FAIL - Should trigger MEM30-C violation
 *
 * Unlike the pass fixture, the else branch here frees the pointer but does
 * NOT terminate (no return/goto/break/continue), so execution falls through
 * to the use right after the if -- a genuine use-after-free that the
 * else_clause-unwrap fix must not mask.
 */

#include <stdlib.h>

extern void use(char *p);

void free_in_else_no_terminator(char *buf, int cond)
{
	if (cond) {
		buf[0] = 'x';
	} else {
		free(buf);
	}

	use(buf);
}
