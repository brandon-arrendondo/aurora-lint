/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM30-C violation
 *
 * Code inside #if 0 ... #endif blocks is never compiled and must not be
 * analysed. Mirrors FP-002 from the Catapult RC624 firmware review where
 * aurora-lint flagged an integer macro (FAULT_WASTE_BIN_FULL) inside a #if 0 block
 * as "use-after-free: passing freed pointer to function."
 */

#include <stdlib.h>

#define FAULT_MASK 0x04

/* Integer macro referenced in dead code — cannot be a freed pointer */
void test_integer_macro_in_dead_code(void)
{
    int *ptr = malloc(sizeof(int));
    if (ptr) {
        *ptr = 42;
    }
    free(ptr);
    ptr = NULL;

#if 0
    /* FAULT_MASK is an integer constant, not a heap pointer. This block
     * is never compiled; aurora-lint must not flag it as use-after-free. */
    some_function(FAULT_MASK);
#endif
}

/* Freed pointer used only inside dead code — not a UAF */
void test_freed_ptr_in_dead_code(void)
{
    int *data = malloc(100 * sizeof(int));
    free(data);
    data = NULL;

#if 0
    /* data is NULL here and also dead code — no UAF to report */
    *data = 1;
    some_function(data);
#endif
}

/* Dead function definition — must not be analysed */
#if 0
void dead_function(void)
{
    int *p = malloc(8);
    free(p);
    free(p);   /* double-free, but inside #if 0 — must not be flagged */
}
#endif

int main(void)
{
    test_integer_macro_in_dead_code();
    test_freed_ptr_in_dead_code();
    return 0;
}
