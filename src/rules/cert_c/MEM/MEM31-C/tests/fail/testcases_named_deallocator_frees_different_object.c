/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 *
 * Guards against overcrediting the name-shaped deallocator fallback: a
 * function whose name looks like a deallocator but frees a different
 * object than the one it was handed (here a static scratch buffer, not
 * its own parameter) must not be credited with releasing its argument, so
 * the caller's allocation still leaks.
 */
#include <stdlib.h>

struct widget {
    int value;
};

static char scratch_buf[64];
static void *scratch_ptr = scratch_buf;

static void widget_free(struct widget *w) {
    /* Frees an unrelated static resource, not `w`. */
    (void)w;
    free(scratch_ptr);
}

void use_widget(void) {
    struct widget *w = malloc(sizeof(struct widget));
    if (!w) {
        return;
    }
    widget_free(w);
}
