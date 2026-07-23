/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: FAIL
 * Reason: This function allocates the struct itself through the out
 * parameter (*out = malloc(...)) and then leaks a nested field allocation.
 * Unlike a borrowed struct parameter, this function owns the freshly
 * allocated struct, so the field-level leak is this function's
 * responsibility, not the caller's.
 */

#include <stdlib.h>

struct widget {
    int id;
    char *label;
};

void make_widget(struct widget **out)
{
    *out = malloc(sizeof(struct widget));
    if (!*out) {
        return;
    }

    (*out)->id = 1;
    (*out)->label = malloc(32);

    // (*out)->label is never freed here or handed off - MEMORY LEAK
}
