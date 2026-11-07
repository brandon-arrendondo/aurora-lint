/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: The code after a success test is the failed path only when the
 * test alone guards it and its branch always leaves. Where the branch falls
 * through, or another condition shares the test, the block can still be held
 * there. A branch that leaves without releasing leaks at its own return, and
 * a new allocation on the failed path is its own leak.
 */

#include <stdlib.h>

void cleanup(void);
void use(void);

int branch_falls_through(void)
{
    char *p = malloc(8); /* Expect: here */
    if (p != NULL) {
        use();
    }
    cleanup();
    return -1; /* Expect: here */
}

int branch_returns_without_releasing(void)
{
    char *p = malloc(8);
    if (p != NULL) {
        use();
        return 0; /* Expect: here */
    }
    cleanup();
    return -1;
}

int test_shared_with_another_condition(int ready)
{
    char *p = malloc(8); /* Expect: here */
    if (p != NULL && ready) {
        free(p);
        return 0;
    }
    cleanup();
    return -1; /* Expect: here */
}

int another_block_on_the_failed_path(void)
{
    char *p = malloc(8);
    char *q = malloc(8); /* Expect: here */
    if (p != NULL) {
        free(p);
        free(q);
        return 0;
    }
    return -1; /* Expect: here */
}

int allocated_again_on_the_failed_path(void)
{
    char *p = malloc(8);
    if (p != NULL) {
        free(p);
        return 0;
    }
    p = malloc(16); /* Expect: here */
    return -1; /* Expect: here */
}

int branch_jumps_out_of_a_loop_still_holding_it(int more)
{
    char *p = malloc(8); /* Expect: here */
    while (more) {
        if (p) {
            use();
            break;
        }
        cleanup();
    }
    return 0; /* Expect: here */
}
