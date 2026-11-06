/*
 * Rule: DCL03-C
 * Source: synthetic
 * Status: PASS - An assertion over a macro that reads an object is not a constant one
 *
 * A static assertion needs an integer constant expression (C11 6.6). A
 * macro spelled in capitals is not one when its replacement list reads an
 * object, an address the linker places, so the runtime assertion is the
 * only one that can be made. A name nothing in reach defines is not shown
 * to be a constant either.
 */
#include <assert.h>

extern char ki_end[];
#define TOP ((unsigned long)ki_end)

void check_layout(unsigned long base)
{
    assert(TOP > base);
    assert(TOP != 0);
    assert(UNSEEN_LIMIT > 4);
}
