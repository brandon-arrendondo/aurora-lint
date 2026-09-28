/*
 * Rule: ERR33-C
 * Status: FAIL - mbrtowc() returns (size_t)-1 on an encoding error. Testing
 * only for (size_t)-2, an incomplete sequence, lets the error through as a
 * byte count.
 */

#include <wchar.h>

const char *skip(const char *s, mbstate_t *st) {
    wchar_t wc;
    size_t n = mbrtowc(&wc, s, 4, st);
    if (n == (size_t)-2) {
        return NULL;
    }
    return s + n;
}
