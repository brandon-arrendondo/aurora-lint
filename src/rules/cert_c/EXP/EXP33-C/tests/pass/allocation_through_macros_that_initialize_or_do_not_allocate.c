/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger EXP33-C violation
 *
 * Allocations that leave nothing uninitialized to read: a zeroing
 * allocator through a function-like macro or an alias, a macro that names
 * an allocator only inside a string, and a conditional whose other arm
 * points at initialized memory (p is assigned on every path; only the
 * malloc arm's content differs, which the analysis does not split).
 */

#include <stdlib.h>

#define zero_buf(n) calloc(1, n)
#define get_zeroed calloc
#define label(s) (s)

char zeroing_macro(void) {
    char *p = zero_buf(8);
    char c = p[0];
    free(p);
    return c;
}

char zeroing_alias(void) {
    char *p = get_zeroed(8, 1);
    char c = p[0];
    free(p);
    return c;
}

char string_through_macro(void) {
    const char *p = label("malloc(8)");
    return p[0];
}

char conditional_with_initialized_arm(size_t n) {
    static char fallback[8];
    char *p = n ? malloc(n) : fallback;
    return p[0];
}
