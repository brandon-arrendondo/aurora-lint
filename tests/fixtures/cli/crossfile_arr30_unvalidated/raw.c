/*
 * Cross-file caller-validation test — the disqualifying caller.
 *
 * Same project as the validated fixture plus this third translation unit,
 * which passes `index` straight through with no range check. One unguarded
 * call site anywhere in the project must disqualify the parameter, so
 * `invoke_inject` stays flagged.
 */

#include "invoke.h"

int raw_inject(unsigned long *lr, unsigned long index, unsigned long virq)
{
    return invoke_inject(lr, index, virq);
}
