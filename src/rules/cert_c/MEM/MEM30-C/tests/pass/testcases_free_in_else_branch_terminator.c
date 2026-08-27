/*
 * Rule: MEM30-C
 * Source: hostap ground-truth audit (task 544/563)
 * Status: PASS - Should NOT trigger MEM30-C violation
 *
 * Regression: tree-sitter-c wraps an `else` branch's body in its own
 * `else_clause` node, distinct from the bare statement/compound_statement
 * node the `then` branch's `consequence` field points to directly. The
 * checker's branch-terminator detection didn't unwrap that wrapper, so a
 * free-then-return sitting in an ELSE arm (or the final `else` of a longer
 * if/else-if/else chain, mirroring hostap's wpa_parse_cipher) was never
 * recognized as terminating -- the freed state leaked into the "neither
 * branch returns" merge and falsely poisoned the fall-through code after
 * the whole if, or a later free of the same pointer.
 */

#include <stdlib.h>

extern int os_strcmp(const char *a, const char *b);

int free_in_else_if_chain(char *buf, const char *start)
{
	int val = 0;

	if (os_strcmp(start, "A") == 0)
		val |= 1;
	else if (os_strcmp(start, "B") == 0)
		val |= 2;
	else {
		free(buf);
		return -1;
	}

	val += 1;
	free(buf); /* not a double-free: only reached when the else arm above did not run */
	return val;
}

int free_in_plain_else(char *buf, int cond)
{
	if (cond) {
		buf = NULL;
	} else {
		free(buf);
		return -1;
	}

	return buf != NULL; /* not use-after-free: only reached via the then-branch */
}
