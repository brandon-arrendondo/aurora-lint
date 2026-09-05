/*
 * Rule: MEM30-C
 * Source: hostap ground-truth audit (task 544/563)
 * Status: PASS - Should NOT trigger MEM30-C violation
 *
 * Regression: mirrors hostap's os_realloc, a project realloc wrapper whose
 * real body (malloc new, copy, free old) legitimately frees its own first
 * argument unconditionally -- a cross-file FunctionSummary correctly
 * credits it with `unconditional_frees_params`. But the call-site handling
 * gave that summary priority over the name-based REALLOC heuristic, so
 * `nbuf = os_realloc(subelem, n)` was treated as an ordinary `free(subelem)`
 * instead of the realloc-grow idiom (pending invalidation, cleared by the
 * `subelem = nbuf` reassignment on success) -- fabricating a double-free
 * across every sequential realloc-grow block in the same function.
 */

extern void *os_malloc(unsigned long n);
extern void os_free(void *p);

void *os_realloc(void *ptr, unsigned long size)
{
	void *n = os_malloc(size);
	if (n == 0)
		return 0;
	os_free(ptr);
	return n;
}

void *grow_twice(void *subelem, unsigned long len1, unsigned long len2)
{
	void *nbuf = os_realloc(subelem, len1);
	if (nbuf == 0) {
		os_free(subelem);
		return 0;
	}
	subelem = nbuf;

	nbuf = os_realloc(subelem, len2);
	if (nbuf == 0) {
		os_free(subelem);
		return 0;
	}
	subelem = nbuf;

	return subelem;
}
