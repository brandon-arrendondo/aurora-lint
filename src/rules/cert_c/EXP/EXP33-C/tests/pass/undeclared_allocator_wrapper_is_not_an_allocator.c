/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger EXP33-C violation
 *
 * A function whose body returns an allocator's result is not itself an
 * allocator until the project declares it one ([environment.allocators]):
 * what it hands back is its contract to state, not something read off its
 * body. Neither wrapper is declared here, so neither result is taken as
 * uninitialized memory.
 */

#include <stdlib.h>

static char *make_buffer(size_t n) {
    return malloc(n);
}

static char *grow_buffer(char *old, size_t n) {
    return realloc(old, n);
}

char read_from_undeclared_malloc_wrapper(void) {
    char *p = make_buffer(8);
    char c = p[0];
    free(p);
    return c;
}

char read_from_undeclared_realloc_wrapper(char *old) {
    char *p = grow_buffer(old, 16);
    char c = p[0];
    free(p);
    return c;
}
