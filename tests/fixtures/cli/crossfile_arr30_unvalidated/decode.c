/*
 * Cross-file caller-validation test — the "decode" half, in its own
 * translation unit. Range-checks `index` before handing it to the callee.
 */

#include "invoke.h"

int decode_inject(unsigned long *lr, unsigned long index, unsigned long virq)
{
    if (index >= NUM_LIST_REGS) {
        return -1;
    }
    return invoke_inject(lr, index, virq);
}
