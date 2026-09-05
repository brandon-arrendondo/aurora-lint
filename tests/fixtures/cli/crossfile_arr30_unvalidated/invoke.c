/*
 * Cross-file caller-validation test — the "act" half.
 *
 * `invoke_inject` indexes `lr` with its own parameter and re-checks nothing.
 * Read on its own that is ARR30-C's unvalidated-function-parameter-index
 * finding; its only caller in the project range-checks `index` first, and
 * that caller lives in another file, so only the prescan's project-wide
 * `callsite_param_validated` summary can see it.
 */

#include "invoke.h"

int invoke_inject(unsigned long *lr, unsigned long index, unsigned long virq)
{
    lr[index] = virq;
    return 0;
}
