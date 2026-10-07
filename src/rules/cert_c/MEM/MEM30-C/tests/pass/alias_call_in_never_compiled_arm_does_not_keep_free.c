/*
 * Rule: MEM30-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Description: A call inside #if 0 is never compiled, so its argument count
 * says nothing about which XFREE is in force. Its one argument would fit
 * the C library's free(), but every live call passes three, which
 * `free(p, heap, type)` cannot take: in any build that compiles them, XFREE
 * is the three-argument macro. Counting the dead call kept free() and made
 * the two releases at the end one double free of the type constant, the
 * third argument.
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
#if 0
	XFREE(dh);
#endif
done:
	if (dh)
		XFREE(dh, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	XFREE(secret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	return (int) n;
}
