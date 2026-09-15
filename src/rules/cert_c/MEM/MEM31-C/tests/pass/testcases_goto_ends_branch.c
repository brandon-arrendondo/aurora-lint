/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: PASS
 * Reason: A branch that ends in `goto` leaves the sequential flow exactly as
 * one ending in `return` does. The free inside `if (result) { free(session);
 * goto out; }` happens only on the path that jumps to the label; the free
 * below the `if` runs only on the path where result is zero. Neither path
 * frees twice. The shape is curl's lib/vtls/wolfssl.c:552/571 and
 * :1178/1183.
 */

#include <stdlib.h>

int reuse(void *session);
int build(void *buf);

int free_then_goto_then_free_below(void)
{
	int result = 0;
	void *session = malloc(32);
	if (!session)
		return -1;

	result = reuse(session);
	if (result) {
		free(session);
		goto out;
	}
	free(session);
	result = 0;
out:
	return result;
}

/* The same, where the branch is the function's only cleanup of `c` on that
 * path and the label does not free it again. */
int goto_branch_frees_then_label_returns(void)
{
	int result;
	void *c = malloc(16);
	if (!c)
		return -1;
	result = build(c);
	if (!result) {
		free(c);
		goto out;
	}
	free(c);
	return 0;
out:
	return -1;
}
