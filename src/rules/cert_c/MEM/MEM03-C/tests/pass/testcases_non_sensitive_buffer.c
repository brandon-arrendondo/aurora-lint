/*
 * Rule: MEM03-C
 * Source: testcases
 * Status: PASS - MEM03-C must only flag plausibly-sensitive buffers
 * Description: freeing/reallocating a generic, non-sensitive buffer
 * without a prior memset is not a MEM03-C violation (task 317).
 */

#include <stdlib.h>
#include <string.h>

void testcase_generic_buffer_no_clear_needed(void) {
    char *buf = (char *)malloc(100);
    if (!buf) {
        return;
    }
    /* Process buf... */
    free(buf);
}

void testcase_generic_buffer_realloc_no_clear_needed(void) {
    char *ctx = (char *)malloc(100);
    if (!ctx) {
        return;
    }
    size_t new_size = 200;
    ctx = (char *)realloc(ctx, new_size);
    free(ctx);
}
