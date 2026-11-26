/*
 * Rule: MEM31-C
 * Source: synthetic
 * Status: FAIL - A block shared by a chained assignment is never freed
 * Expect: count=3
 *
 * `first = last = key` gives the block to both names, but nothing frees
 * or returns it under any of them. It is reported under each name that
 * holds it, as `last = key; first = last;` is.
 */
#include <stdlib.h>

void block_held_by_every_name_and_dropped(void)
{
    char *first, *last, *key;

    key = malloc(16);
    if (!key)
        return;
    first = last = key;
    first[0] = last[0] = '\0';
}
