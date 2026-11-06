/*
 * Rule: CON07-C
 * Source: synthetic
 * Status: FAIL - The static is declared in the arm the function is in
 *
 * An include guard holds both, so every configuration that compiles the
 * function compiles the static it updates.
 */

#ifndef COUNTERS_H
#define COUNTERS_H

static long total;

void add(long n)
{
    total += n;
}

#endif
