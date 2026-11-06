/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: FAIL - A const amount of the guard around the shift is past the width
 *
 * `gs` is a const object of the guard the function is in, so the shift is
 * by 40, which is past the precision of `int`.
 */

#ifndef MASK_H
#define MASK_H

static const int gs = 40;

int mask(void)
{
    return 1 << gs;
}

#endif
