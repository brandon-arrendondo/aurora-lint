/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: FAIL - an int size after a handle named for a count
 *
 * pCount is the pool, a pointer, and is not the size; nBytes, the int after
 * it, is the size this allocation is given.
 */
struct pool { int used; };

void *pool_alloc(struct pool *pCount, int nBytes);

void *grow(struct pool *pCount, int nBytes) {
    return pool_alloc(pCount, nBytes);
}
