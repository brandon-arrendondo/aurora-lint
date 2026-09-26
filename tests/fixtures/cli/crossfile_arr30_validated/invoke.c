/*
 * Cross-file caller-validation test -- the "act" half.
 *
 * `invoke_inject` indexes `lr` with its own parameter and re-checks nothing.
 * Its only caller in the project range-checks `index` first, from another
 * file. That does not prove the index valid: the function is exported, so
 * callers outside the project can pass anything, and ARR30-C reports the
 * unvalidated-function-parameter index (ADR-0011).
 */

#include "invoke.h"

int invoke_inject(unsigned long *lr, unsigned long index, unsigned long virq)
{
    lr[index] = virq;
    return 0;
}
