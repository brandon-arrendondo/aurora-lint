/*
 * Rule: WIN00-C
 * Status: PASS - Should NOT trigger WIN00-C violation
 *
 * DLL_FLAGS is undefined and defined again with a search-path flag. Its
 * two definitions differ, so its value at the call is not taken from
 * either, and the call is not proven unspecific.
 */

#include <windows.h>

#define DLL_FLAGS (LOAD_LIBRARY_AS_DATAFILE | 0)
#undef DLL_FLAGS
#define DLL_FLAGS (LOAD_LIBRARY_SEARCH_SYSTEM32 | 0)

void load_resource_library(void)
{
    HMODULE h = LoadLibraryExW(L"resources.dll", NULL, DLL_FLAGS);
    (void)h;
}
