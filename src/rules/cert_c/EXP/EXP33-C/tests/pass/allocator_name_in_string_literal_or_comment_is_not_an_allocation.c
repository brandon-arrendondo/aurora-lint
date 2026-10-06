/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: PASS - Should NOT trigger EXP33-C violation
 *
 * An initializer that only spells an allocator -- inside a string literal, or
 * a comment within parentheses -- is not an allocation: the pointer holds a
 * string, so reading through it reads initialized data.
 */

#include <stddef.h>

char from_malloc_text(void) {
    const char *p = ")malloc(";
    return p[0];
}

char from_calloc_text(void) {
    const char *p = "calloc(4, 1)";
    return p[0];
}

char from_comment(void) {
    const char *p = ("x" /* malloc(1) */);
    return p[0];
}
