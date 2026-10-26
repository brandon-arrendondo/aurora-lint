/*
 * Rule: PRE31-C
 * Status: FAIL - Should trigger PRE31-C violation
 * Reason: the file replaces getc only under LOCKED_IO, and the call
 * compiles only without it, so the call is <stdio.h>'s getc, which may
 * evaluate its stream more than once.
 */

#include <stdio.h>

#ifdef LOCKED_IO
#undef getc
#define getc(f) fgetc(f)
#endif

int read_next(FILE **streams, int i) {
#ifndef LOCKED_IO
    return getc(streams[i++]);  // Expect: here
#else
    return fgetc(streams[i]);
#endif
}
