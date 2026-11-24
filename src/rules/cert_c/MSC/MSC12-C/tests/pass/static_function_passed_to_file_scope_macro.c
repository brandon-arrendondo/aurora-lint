/*
 * Rule: MSC12-C
 * Source: synthetic
 * Status: PASS - a code-generating macro invoked at file scope takes the static by name
 *
 * heap_gen comes from a header the scan does not read; the parse reads its
 * invocation as a prototype whose parameters name the comparator.
 */
#include "heap_gen.h"

struct item {
    int age;
};

static int item_age_cmp(const struct item *a, const struct item *b)
{
    return a->age - b->age;
}

heap_gen(, item_heap, struct item, link, item_age_cmp)

int item_count(void)
{
    return 0;
}
