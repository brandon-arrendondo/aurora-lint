/*
 * Rule: MEM31-C
 *
 * Status: PASS - Should NOT trigger MEM31-C violation
 *
 * grow() reallocates in one build and is a stub that returns NULL in the
 * other. Its caller frees the old block only when grow() returned NULL,
 * which is the block grow() left alone in either build: no double free.
 */
#include <stdlib.h>
#include <string.h>

#ifdef NO_HEAP
void *grow(void *ptr, size_t size)
{
    (void)ptr;
    (void)size;
    return NULL;
}
#else
void *grow(void *ptr, size_t size)
{
    void *n = malloc(size);
    if (n == NULL)
        return NULL;
    memcpy(n, ptr, size / 2);
    free(ptr);
    return n;
}
#endif

int extend(void)
{
    char *buf = malloc(16);
    char *nbuf;
    if (buf == NULL)
        return -1;
    buf[0] = 'x';
    nbuf = grow(buf, 32);
    if (nbuf == NULL) {
        free(buf);
        return -1;
    }
    buf = nbuf;
    free(buf);
    return 0;
}
