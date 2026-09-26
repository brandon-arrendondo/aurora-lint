/*
 * Rule: WIN00-C
 * Source: testcases
 * Status: FAIL - Should trigger WIN00-C violation
 *
 * DLL_LOAD_FLAGS is defined as LOAD_LIBRARY_AS_DATAFILE | 0, a value with no
 * search-path control bit, so the DLL is found through the default search
 * path.
 */

#include <windows.h>

#define DLL_LOAD_FLAGS (LOAD_LIBRARY_AS_DATAFILE | 0)

void load_resource_library(void)
{
    HMODULE h = LoadLibraryExW(L"resources.dll", NULL, DLL_LOAD_FLAGS);  /* VIOLATION */
    (void)h;
}
