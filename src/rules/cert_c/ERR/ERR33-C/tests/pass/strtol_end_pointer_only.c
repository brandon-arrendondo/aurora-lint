/*
 * Rule: ERR33-C
 * Status: PASS - a strto* result is checked through the end pointer it was
 * given, whatever that pointer is named, with no errno read at all.
 */

#include <stdlib.h>

long parse(const char *s) {
    char *stop;
    long v = strtol(s, &stop, 10);
    if (stop == s || *stop != '\0') {
        return -1;
    }
    return v;
}
