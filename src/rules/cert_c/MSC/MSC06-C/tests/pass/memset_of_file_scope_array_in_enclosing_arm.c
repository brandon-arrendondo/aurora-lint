/*
 * Rule: MSC06-C
 * Source: synthetic
 * Status: PASS - The array has file scope, inside the arm the function is in
 *
 * It does not go out of scope when the function returns, so the memset is
 * not a dead store.
 */

#include <string.h>

#ifdef WITH_TABLE

static char table[8];

void clear(void)
{
    memset(table, 0, sizeof(table));
}

#endif
