/*
 * Rule: WIN00-C
 * Source: testcases
 * Status: PASS - Should NOT trigger WIN00-C violation
 *
 * The flags are judged by what they are, not how they are spelled.
 * MY_SEARCH is defined as LOAD_LIBRARY_SEARCH_SYSTEM32, and the literal
 * 0x00000800 has the same value, so both calls restrict the DLL search to
 * System32. An undefined ALL_CAPS name proves nothing either way.
 */

#include <windows.h>

#define MY_SEARCH LOAD_LIBRARY_SEARCH_SYSTEM32

void load_libraries(void)
{
    HMODULE a = LoadLibraryExW(L"version.dll", NULL, MY_SEARCH);
    HMODULE b = LoadLibraryExW(L"version.dll", NULL, 0x00000800);
    HMODULE c = LoadLibraryExW(L"version.dll", NULL, PLATFORM_LOAD_FLAGS);
    (void)a;
    (void)b;
    (void)c;
}
