/*
 * Rule: WIN00-C
 * Status: PASS - Should NOT trigger WIN00-C violation
 *
 * DLL_FLAGS has a search-path flag in one branch and none in the other.
 * Which branch is compiled is unknown, so the call is not proven unspecific.
 */

#include <windows.h>

#ifdef USE_SYSTEM_DIRECTORY
#define DLL_FLAGS (LOAD_LIBRARY_SEARCH_SYSTEM32 | 0)
#else
#define DLL_FLAGS (LOAD_LIBRARY_AS_DATAFILE | 0)
#endif

void load_resource_library(void)
{
    HMODULE h = LoadLibraryExW(L"resources.dll", NULL, DLL_FLAGS);
    (void)h;
}
