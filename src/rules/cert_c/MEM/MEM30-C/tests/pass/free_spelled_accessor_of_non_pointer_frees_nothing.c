/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM30-C violation
 *
 * seL4 spells ordinary accessors with FREE in the name. Nothing is released
 * through an argument that is not a pointer: `cap_get_capFreeIndex` takes a
 * `cap_t` BY VALUE and `OFFSET_TO_FREE_INDEX` an integer counter, and marking
 * either freed made every later read of it a use-after-free.
 */
#include <stddef.h>

typedef struct cap {
    unsigned long words[2];
} cap_t;

unsigned long cap_get_capFreeIndex(cap_t cap);
unsigned long OFFSET_TO_FREE_INDEX(unsigned long offset);
void use_cap(cap_t cap, unsigned long index);

void reset_untyped(cap_t cap) {
    unsigned long freeIndex = cap_get_capFreeIndex(cap);
    unsigned long offset = 0;

    offset = OFFSET_TO_FREE_INDEX(offset);
    use_cap(cap, freeIndex);
    use_cap(cap, offset);
}
