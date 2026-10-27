/*
 * Rule: DCL37-C
 * Status: PASS - each feature-test macro on the cited list is defined. The
 * names are reserved, but the standard or implementation that documents each
 * one tells the program to define it to request features.
 */

#define __STDC_WANT_LIB_EXT1__ 1
#define __STDC_WANT_IEC_60559_EXT__ 1
#define __STDC_WANT_IEC_60559_TYPES_EXT__ 1
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#define _POSIX_SOURCE 1
#define _ISOC99_SOURCE 1
#define _ISOC11_SOURCE 1
#define _ISOC23_SOURCE 1
#define _ISOC2X_SOURCE 1
#define _LARGEFILE_SOURCE 1
#define _LARGEFILE64_SOURCE 1
#define _FILE_OFFSET_BITS 64
#define _TIME_BITS 64
#define _BSD_SOURCE 1
#define _SVID_SOURCE 1
#define _DEFAULT_SOURCE 1
#define _ATFILE_SOURCE 1
#define _GNU_SOURCE 1
#define _REENTRANT 1
#define _THREAD_SAFE 1
#define _FORTIFY_SOURCE 2

#include <stdio.h>

int main(void) { return 0; }
