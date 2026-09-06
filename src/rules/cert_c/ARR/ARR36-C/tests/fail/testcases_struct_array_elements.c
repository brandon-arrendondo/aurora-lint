/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to
 *       the same array
 * Status: FAIL
 * Reason: 'slots[0].data' and 'slots[1].data' are array members of two
 *         DIFFERENT structs, so they are two arrays. The counterpart to
 *         pass/testcases_overlay_struct_in_buffer.c: resolving a field path to
 *         its root would make both of these 'slots' and lose the distinction,
 *         which is why a subscript stops that walk.
 */

#include <stddef.h>

struct slot {
    int data[8];
    int used;
};

void compare_slot_arrays(void)
{
    struct slot slots[4];

    int *first = slots[0].data;
    int *second = slots[1].data;

    if (first < second) {  /* VIOLATION */
        slots[0].used = 1;
    }
}

int main(void)
{
    compare_slot_arrays();
    return 0;
}
