/*
 * Rule: MSC06-C
 * Source: synthetic
 * Status: FAIL - A local array hides the file-scope one of the enclosing arm
 *
 * The block's declaration is nearer than any arm's, so this `table` goes out
 * of scope at the return and the memset is a dead store.
 */

#include <string.h>

#ifdef WITH_TABLE

static char table[8];

void clear(void)
{
    char table[8];

    table[0] = 1;
    memset(table, 0, sizeof(table));
}

#endif
