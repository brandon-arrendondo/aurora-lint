/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: An element of an array of pointers is a pointer, so `b[0] < 0`
 * is never true and does not test whether the allocation failed. Each return
 * below leaks the block.
 */

#include <stdlib.h>

typedef char *str_t;

struct holder {
    char *bufs[2];
};

int fill(void *buf, size_t len);

int element_of_an_array_of_pointers(void)
{
    char *bufs[2];
    bufs[0] = malloc(8);
    if (bufs[0] < 0) {
        return -1; /* Expect: here */
    }
    if (bufs[0] == NULL) {
        return -1;
    }
    fill(bufs[0], 8);
    free(bufs[0]);
    return 0;
}

int element_of_an_array_of_a_pointer_typedef(void)
{
    str_t bufs[2];
    bufs[0] = malloc(8);
    if (bufs[0] < 0) {
        return -1; /* Expect: here */
    }
    if (bufs[0] == NULL) {
        return -1;
    }
    fill(bufs[0], 8);
    free(bufs[0]);
    return 0;
}

int element_of_an_array_member(void)
{
    struct holder h;
    h.bufs[0] = malloc(8);
    if (h.bufs[0] < 0) {
        return -1; /* Expect: here */
    }
    if (h.bufs[0] == NULL) {
        return -1;
    }
    fill(h.bufs[0], 8);
    free(h.bufs[0]);
    return 0;
}
