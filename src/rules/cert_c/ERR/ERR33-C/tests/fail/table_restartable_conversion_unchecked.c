/*
 * Rule: ERR33-C
 * Status: FAIL - mbrtowc() returns (size_t)-1 on an encoding error. The
 * count is used as a length without that test.
 */

#include <wchar.h>

const char *skip_char(const char *s, mbstate_t *state) {
    wchar_t wc;
    size_t n = mbrtowc(&wc, s, 4, state);
    return s + n;
}
