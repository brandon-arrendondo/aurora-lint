/*
 * Header-declared on purpose: a declaration other translation units can see
 * is what makes `invoke_inject` exported, and its caller set open.
 */
#ifndef INVOKE_H
#define INVOKE_H

#define NUM_LIST_REGS 4

int invoke_inject(unsigned long *lr, unsigned long index, unsigned long virq);

#endif
