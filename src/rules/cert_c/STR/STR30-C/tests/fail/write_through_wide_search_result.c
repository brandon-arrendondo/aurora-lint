/*
 * Rule: STR30-C
 * Source: synthetic
 * Status: FAIL - wcschr returns a pointer into the wide literal it searched
 */

#include <wchar.h>

void func(void)
{
    wchar_t *w = wcschr(L"hello", L'l');
    if (w)
        *w = L'L';
}
