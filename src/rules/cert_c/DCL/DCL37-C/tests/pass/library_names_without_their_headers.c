/*
 * Rule: DCL37-C
 * Status: PASS - a library name such as `bool`, `true`, `false` or `SIZE_MAX`
 * is reserved only where the file includes one of the headers that define it
 * (C 7.1.3), and this file includes none of them.
 */

#include <string.h>

typedef enum bool { false, true } bool;

static const int SIZE_MAX = 4096;

bool fits(const char *s) { return strlen(s) < (unsigned)SIZE_MAX ? true : false; }
