/*
 * Rule: EXP34-C - Do not dereference null pointers
 * Status: PASS - Should NOT trigger EXP34-C violation
 * Reason: sizeof, _Alignof and GNU typeof never evaluate their operand, so
 *         `*p` there reads nothing even when p may be NULL. Companion to
 *         fail/testcases_deref_inside_assert_argument.c: an assert's argument,
 *         unlike these, is evaluated.
 * Settings: free_null_is_noop=true
 *         (the trailing free() of a possibly-null pointer is not what this
 *         fixture tests, so the free(NULL) contract is held on)
 */

#include <stdlib.h>

struct item {
    int n;
};

size_t measure(void) {
    struct item *p = malloc(sizeof(struct item));
    size_t size = sizeof(*p) + sizeof p->n;
    size_t align = _Alignof(*p);
    __typeof__(p->n) copy = 0;
    typeof(*p) *again = NULL;
    free(p);
    return size + align + (size_t)copy + (again != NULL);
}
