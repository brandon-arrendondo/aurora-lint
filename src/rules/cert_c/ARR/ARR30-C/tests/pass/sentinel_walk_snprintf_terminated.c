/*
 * Rule: ARR30-C
 * Source: task 1021 (NUL-sentinel walk over a fixed-size char array)
 * Status: PASS - Should NOT trigger ARR30-C violation
 * Reason: the same terminator-bounded walk as
 * tests/pass/sentinel_walk_zero_initialized.c, with the terminator
 * established by the write rather than by the declaration: snprintf always
 * places a NUL inside the length it is given, and that length is the whole
 * array. Also covers the bare-truth-value spelling of the sentinel test.
 */

#include <stdio.h>

void SanitizePath(const char *fileName)
{
    char buf[128];
    snprintf(buf, sizeof(buf), "%s", fileName);
    for (int i = 0; buf[i]; i++)
    {
        if (buf[i] == '/') buf[i] = '_';
    }
}
