/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - The value past the end is overwritten by an arm always taken
 *
 * The file defines the macro, so nothing passes around the arm.
 */

#define B
int buf[4];
int c;

int element(void)
{
    int i = 9;
#ifdef B
    i = 1;
#endif
    return buf[i];
}
