/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: The guard on an earlier fix's failure-branch restore. The old block
 * is spared only on the path where the realloc-shaped wrapper returned NULL.
 * On the SUCCESS path the wrapper really did take it, so freeing it there is
 * a genuine double free and must still be reported -- otherwise the restore
 * would be a blanket suppressor for every realloc wrapper.
 */

#include <stdlib.h>

void *wrapper_realloc(void *ptr, size_t size) {
    void *n;

    if (ptr == NULL) {
        return malloc(size);
    }
    n = malloc(size);
    if (n == NULL) {
        return NULL;
    }
    free(ptr);
    return n;
}

extern char *make_block(int *len);

char *free_old_after_success(int extra) {
    int len = 0;
    char *nbuf;
    char *block = make_block(&len);

    if (!block) {
        return NULL;
    }
    nbuf = wrapper_realloc(block, len + extra);
    if (!nbuf) {
        return NULL;
    }
    free(block); /* VIOLATION: the wrapper took 'block' when it succeeded */
    return nbuf;
}
