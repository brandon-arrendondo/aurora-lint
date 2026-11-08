/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The arm storing past the end needs a macro undefined
 *
 * The file defines the macro, so that arm is dead.
 */

#define B
int buf[4];
int c;

int element(void)
{
    int i;
#ifndef B
    i = 9;
#else
    i = 1;
#endif
    return buf[i];
}
