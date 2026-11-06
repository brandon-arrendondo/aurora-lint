/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: A typedef can hide the pointer. `b < 0` on a typedef of a
 * pointer is never true, whatever the declaration spells, so it does not test
 * whether the allocation failed, and each return below leaks the block.
 */

#include <stdlib.h>

typedef char *str_t;
typedef str_t text_t;
typedef const char *cstr_t;
typedef struct node {
    int value;
} *node_p;

int fill(void *buf, size_t len);

int through_a_typedef(void)
{
    str_t b = malloc(8);
    if (b < 0) {
        return -1; /* Expect: here */
    }
    if (b == NULL) {
        return -1;
    }
    fill(b, 8);
    free(b);
    return 0;
}

int through_a_chain_of_typedefs(void)
{
    text_t b = malloc(8);
    if (b < 0) {
        return -1; /* Expect: here */
    }
    if (b == NULL) {
        return -1;
    }
    fill(b, 8);
    free(b);
    return 0;
}

int through_a_typedef_of_a_pointer_to_const(void)
{
    cstr_t b = malloc(8);
    if (b < 0) {
        return -1; /* Expect: here */
    }
    if (b == NULL) {
        return -1;
    }
    free((void *)b);
    return 0;
}

int through_a_struct_pointer_typedef(void)
{
    node_p n = malloc(sizeof(*n));
    if (n < 0) {
        return -1; /* Expect: here */
    }
    if (n == NULL) {
        return -1;
    }
    fill(n, sizeof(*n));
    free(n);
    return 0;
}

int through_a_typedef_in_a_block(void)
{
    typedef char *local_t;
    local_t b = malloc(8);
    if (b < 0) {
        return -1; /* Expect: here */
    }
    if (b == NULL) {
        return -1;
    }
    fill(b, 8);
    free(b);
    return 0;
}
