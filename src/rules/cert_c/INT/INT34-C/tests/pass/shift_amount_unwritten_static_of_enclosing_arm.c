/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: PASS - An unwritten static amount declared in the guard around the shift
 *
 * Nothing in the file writes `gs`, so it holds its initializer and the
 * shift is by 3, the same as with no guard around the file.
 */

#ifndef MASK_H
#define MASK_H

static int gs = 3;

int mask(void)
{
    return 1 << gs;
}

#endif
