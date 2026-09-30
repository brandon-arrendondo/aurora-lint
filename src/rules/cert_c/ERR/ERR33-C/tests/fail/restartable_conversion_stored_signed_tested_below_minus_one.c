/*
 * Rule: ERR33-C
 * Status: FAIL - mbrtowc() returns (size_t)-1 on an encoding error. Stored
 * in an int, that is -1, and (size_t)-2 is -2: `n < -2` is true for
 * neither, so the encoding error goes on as a count.
 */

#include <wchar.h>

const char *skip(const char *s, mbstate_t *st) {
    wchar_t wc;
    int n = mbrtowc(&wc, s, 4, st);
    if (n < -2) {
        return NULL;
    }
    return s + n;
}
