/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: A realloc-shaped wrapper -- one that frees a pointer argument
 * and hands back a fresh block -- takes the old block only when it SUCCEEDS.
 * hostap's os_realloc is written the way a careful wrapper has to be:
 * allocate first, bail out before touching the caller's block. The free then
 * sits at the body's top level, so frees_params records it (correctly, as a
 * MAY fact), and every caller's `nbuf = os_realloc(p, n); if (!nbuf) free(p);`
 * read as a double free of a block that is still alive. The callee's early
 * return and the caller's null test are the same path. Task 1279.
 */

#include <stdlib.h>

void *wrapper_realloc(void *ptr, size_t size) {
    void *n;

    if (ptr == NULL) {
        return malloc(size);
    }
    n = malloc(size);
    if (n == NULL) {
        return NULL; /* the old block is deliberately NOT freed here */
    }
    free(ptr);
    return n;
}

extern char *make_block(int *len);

char *grow_checked(int extra) {
    int len = 0;
    char *nbuf;
    char *block = make_block(&len);

    if (!block) {
        return NULL;
    }
    nbuf = wrapper_realloc(block, len + extra);
    if (!nbuf) {
        free(block);
        return NULL;
    }
    return nbuf;
}

/* The equality spelling of the same test, and the result bound by an
   initializer rather than an assignment. */
char *grow_checked_decl(int extra) {
    int len = 0;
    char *block = make_block(&len);

    if (block == NULL) {
        return NULL;
    }
    char *nbuf = wrapper_realloc(block, len + extra);
    if (nbuf == NULL) {
        free(block);
        return NULL;
    }
    return nbuf;
}
