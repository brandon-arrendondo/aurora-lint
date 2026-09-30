/*
 * Rule: ERR33-C
 * Status: FAIL - on LP64 a long compared with an unsigned int converts the
 * unsigned int, not the long: `n >= (unsigned int)-2` is a signed comparison
 * against 4294967294, and the -1 an encoding error leaves in n is below it.
 */

#include <wchar.h>

int f(const char *s, mbstate_t *st) {
    wchar_t wc;
    long n = mbrtowc(&wc, s, 4, st);
    if (n >= (unsigned int)-2) {
        return -1;
    }
    return (int)n;
}
