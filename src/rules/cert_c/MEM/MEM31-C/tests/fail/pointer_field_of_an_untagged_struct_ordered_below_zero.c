/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: A struct with no tag can still be reached through a pointer
 * typedef, when the same definition also names it. A field of that struct
 * declared as a pointer is never below 0, so `s->f < 0` does not test whether
 * the allocation failed, and each return below leaks the field's block.
 */

#include <stdlib.h>

typedef char *text_t;

typedef struct {
    text_t f;
} named_t, *named_p;

typedef struct {
    text_t f;
} *pointer_first_p, pointer_first_t;

int through_a_sibling_name(void)
{
    named_p s = malloc(16);
    if (s == NULL) {
        return -1;
    }
    s->f = malloc(8);
    if (s->f < 0) {
        free(s);
        return -1; /* Expect: here */
    }
    free(s->f);
    free(s);
    return 0;
}

int through_a_sibling_name_declared_after_the_pointer(void)
{
    pointer_first_p s = malloc(16);
    if (s == NULL) {
        return -1;
    }
    s->f = malloc(8);
    if (s->f < 0) {
        free(s);
        return -1; /* Expect: here */
    }
    free(s->f);
    free(s);
    return 0;
}
