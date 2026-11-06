/*
 * Rule: DCL30-C
 * Source: synthetic
 * Status: FAIL - The object outlived is declared in the arm the function is in
 *
 * `opt` has file scope though a conditional holds it: the function is in
 * the same arm, so the two always compile together.
 */

#include <stdio.h>

#ifdef WITH_OPTIONS

struct options {
    char *name;
} opt;

void configure(void)
{
    char buf[8];

    opt.name = buf;
    puts(opt.name);
}

#endif
