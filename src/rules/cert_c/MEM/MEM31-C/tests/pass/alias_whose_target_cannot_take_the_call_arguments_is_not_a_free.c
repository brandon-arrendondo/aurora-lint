/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: An object-like alias is not a free where the file calls it
 * with arguments its target cannot take. One build configuration of this
 * file makes XFREE the C library's one-argument free(); the other makes it
 * a three-argument call that carries a heap hint and an allocation type.
 * Every call below passes three arguments, so `free(p, heap, type)` would
 * not compile: in any build that compiles them, XFREE is the three-argument
 * macro. Reading them as free() made the two releases at the end one double
 * free of the type constant, the third argument.
 */

#include <stdlib.h>

#define DYNAMIC_TYPE_TMP_BUFFER 38

#ifdef USE_LIBC_ALLOCATOR
#define XMALLOC malloc
#define XFREE free
#else
void *pool_malloc(size_t n, void *heap, int type);
void pool_free(void *p, void *heap, int type);
#define XMALLOC(n, h, t) pool_malloc((n), (h), (t))
#define XFREE(p, h, t) pool_free((p), (h), (t))
#endif

int compute(size_t n)
{
	unsigned char *dh = XMALLOC(n, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	unsigned char *secret = XMALLOC(n, NULL, DYNAMIC_TYPE_TMP_BUFFER);

	if (!dh || !secret)
		goto done;
	secret[0] = dh[0];
done:
	if (dh)
		XFREE(dh, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	XFREE(secret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	return (int) n;
}
