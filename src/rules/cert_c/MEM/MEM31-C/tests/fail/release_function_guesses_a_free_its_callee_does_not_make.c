/*
 * Rule: MEM31-C
 *
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * release() frees its argument in the A build and hands it to up_free() in
 * the other. up_free() is named like a deallocator, but its body frees only
 * a field of what it is handed, so the block itself leaks in that build. A
 * name-shaped free counts for the definition that makes it only when the
 * callee's body does not contradict it, whatever a sibling definition does.
 */
#include <stdlib.h>

struct box {
    char *data;
};

void up_free(struct box *b)
{
    free(b->data);
}

#ifdef A
void release(struct box *p)
{
    free(p);
}
#else
void release(struct box *p)
{
    up_free(p);
}
#endif

void use_box(void)
{
    struct box *b = malloc(sizeof(*b));
    if (b == NULL)
        return;
    b->data = NULL;
    release(b);
}
