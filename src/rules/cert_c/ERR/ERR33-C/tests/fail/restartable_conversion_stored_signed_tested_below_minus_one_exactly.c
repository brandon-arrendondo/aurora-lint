/*
 * Rule: ERR33-C
 * Status: FAIL - mbrtowc()'s encoding error is -1 in an int. `n < -1` is
 * true only for -2 and -3, so the error goes on as a count.
 */

#include <wchar.h>

const char *skip(const char *s, mbstate_t *st) {
    wchar_t wc;
    int n = mbrtowc(&wc, s, 4, st);
    if (n < -1) {
        return NULL;
    }
    return s + n;
}
