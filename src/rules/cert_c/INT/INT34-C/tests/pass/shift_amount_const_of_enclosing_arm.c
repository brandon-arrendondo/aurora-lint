/*
 * Rule: INT34-C
 * Source: synthetic
 * Status: PASS - A const amount declared in the include guard around the shift
 *
 * `gs` is a const object of the guard the function is in, so the shift is
 * by 3, the same as with no guard around the file.
 */

#ifndef MASK_H
#define MASK_H

static const int gs = 3;

int mask(void)
{
    return 1 << gs;
}

#endif
