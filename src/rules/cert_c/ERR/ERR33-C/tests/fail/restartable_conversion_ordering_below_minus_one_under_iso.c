/*
 * Rule: ERR33-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * With no data model declared, only what ISO C guarantees is credited, and
 * ISO C lets size_t be narrower than int. There the unsigned result promotes
 * to int, `n > -3` is a signed comparison, and every result -- a valid
 * count as much as (size_t)-1, 65535 on a 16-bit size_t -- is above -3: the
 * ordering does not single out the encoding error. On a declared LP64 target
 * size_t is 64 bits, the comparison is unsigned, and the same code is a test
 * (tests/pass/restartable_conversion_stored_in_typedef_or_member.c).
 */

#include <wchar.h>

int f(const char *s, mbstate_t *st) {
    wchar_t wc;
    size_t n = mbrtowc(&wc, s, 4, st); /* VIOLATION */
    if (n > -3) {
        return -1;
    }
    return (int)n;
}
