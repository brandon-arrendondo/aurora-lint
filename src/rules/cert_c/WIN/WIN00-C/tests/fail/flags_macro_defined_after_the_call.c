/*
 * Rule: WIN00-C
 * Status: FAIL - Should trigger WIN00-C violation
 *
 * DLL_FLAGS and the macro it is built from are defined after the function
 * that uses them, and still have no search-path control bit.
 */

#include <windows.h>

void load_resource_library(void)
{
    HMODULE h = LoadLibraryExW(L"resources.dll", NULL, DLL_FLAGS);  /* VIOLATION */
    (void)h;
}

#define DLL_FLAGS (DATA_FLAGS | 0)
#define DATA_FLAGS (LOAD_LIBRARY_AS_DATAFILE | 0)
