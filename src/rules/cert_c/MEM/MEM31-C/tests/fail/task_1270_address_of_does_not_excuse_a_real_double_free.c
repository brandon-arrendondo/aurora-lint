/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory exactly once
 * Status: FAIL
 * Reason: The out-parameter rebind of task 1270 clears a freed mark only
 *         where the callee may actually write through the pointer. A
 *         callee whose own body shows it merely READS through it is
 *         positive evidence to the contrary, so the block is still the one
 *         that was released and freeing it again is still a double free.
 *         `safe_free(&p)` is the other excluded shape: it RELEASES the
 *         pointee rather than rebinding it, so the free it performs must
 *         survive.
 */

#include <stdlib.h>

static int peek(char **ro)
{
    return *ro == 0;
}

static void safe_free(void **ptr)
{
    if (ptr && *ptr) {
        free(*ptr);
        *ptr = 0;
    }
}

void reader_does_not_rebind(void)
{
    char *p = malloc(32);

    free(p);
    peek(&p);
    free(p);
}

void pointee_free_is_not_a_rebind(void)
{
    char *q = malloc(32);

    safe_free((void **)&q);
    free(q);
}
