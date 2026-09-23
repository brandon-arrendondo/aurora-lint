/*
 * Rule: MEM31-C
 * Source: hostap src/ap/beacon.c ieee802_11_vendor_ie_concat() call sites
 *         (task 1339)
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * A local declared inside a block, guarded by an early `return` in a
 * nested `if`, then freed on the fall-through path. The walk decided
 * "this branch leaves the flow" by whether a `return` existed ANYWHERE
 * inside it, so the outer branch's freed set was thrown away after the
 * `if` while the allocation it made stayed recorded, and the block was
 * reported "not freed" at the end of the function. The same code with no
 * enclosing block, or with no early return, was always clean. Whether a
 * branch falls through is decided by its LAST statement, looking through
 * an `if`/`else` whose arms both leave.
 */
#include <stdlib.h>

struct wpabuf {
	int len;
};

int matches(struct wpabuf *w);

void guarded_then_freed(const char *ie, size_t len)
{
	if (ie) {
		struct wpabuf *wps = malloc(len);

		if (!wps)
			return;
		free(wps);
	}
}

void freed_on_both_paths(const char *ie, size_t len)
{
	if (ie) {
		struct wpabuf *wps = malloc(len);

		if (wps && !matches(wps)) {
			free(wps);
			return;
		}
		free(wps);
	}
}

void branch_ending_in_if_else_that_both_return(void *p, int x, int a)
{
	if (x) {
		free(p);
		if (a)
			return;
		else
			return;
	}
	free(p);
}
