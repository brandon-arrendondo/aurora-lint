/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - One preprocessor arm declares the index past the end, inside an include guard
 * Expect: count=1
 *
 * The include guard holds both the array and the access, so no other arm
 * can declare the array with another size. The arms that declare the
 * index disagree, and one of them is past the end, so the access is
 * reported with that arm's index.
 */

#ifndef ELEMENT_H
#define ELEMENT_H

char buf[4];

int element(void)
{
#if defined(A)
    int i = 7;
#else
    int i = 2;
#endif
    return buf[i]; /* Expect: here */
}

#endif
