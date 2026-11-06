/*
 * Rule: DCL03-C
 * Source: synthetic
 * Status: FAIL - An assertion over enumerators and macros is a constant one
 * Expect: count=3
 *
 * An enumerator is an integer constant whatever its spelling, as is a
 * macro whose replacement list folds from one, so each assertion could
 * be a static assertion (C11 6.7.10).
 */
#include <assert.h>

enum { slots = 8, slot_bytes = 16 };
#define table_bytes (slots * slot_bytes)

void check_table(void)
{
    assert(slots == 8);
    assert(slot_bytes * slots <= 256);
    assert(table_bytes == 128);
}
