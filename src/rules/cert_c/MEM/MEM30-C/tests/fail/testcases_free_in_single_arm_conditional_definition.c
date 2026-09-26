/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: FAIL - a function defined under a one-arm #if that always frees
 * its argument frees it in the configuration that compiles it, so the
 * caller's later read is a use after free there
 */

#include <stdlib.h>

struct item { int value; };

#ifdef WITH_ITEMS
void item_release(struct item *it)
{
    free(it);
}
#endif

int take(struct item *it)
{
    item_release(it);
    return it->value;
}
