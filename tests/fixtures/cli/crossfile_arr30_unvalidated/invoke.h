/*
 * Header-declared on purpose: the validate-then-act split only needs a
 * cross-file declaration when the two halves live in different translation
 * units, which is exactly the case the project-wide summary exists for.
 */
#ifndef INVOKE_H
#define INVOKE_H

#define NUM_LIST_REGS 4

int invoke_inject(unsigned long *lr, unsigned long index, unsigned long virq);

#endif
