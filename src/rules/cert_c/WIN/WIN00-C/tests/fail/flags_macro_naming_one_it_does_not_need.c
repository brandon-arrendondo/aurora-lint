/*
 * Rule: WIN00-C
 * Status: FAIL - Should trigger WIN00-C violation
 *
 * DLL_FLAGS and SIZE_FLAGS name each other, but DLL_FLAGS needs only the
 * size of SIZE_FLAGS, which is at least 1 whatever it is. DLL_FLAGS is
 * LOAD_LIBRARY_AS_DATAFILE with the low bit, and no search-path flag.
 */

#include <windows.h>

#define DLL_FLAGS (sizeof(SIZE_FLAGS) | LOAD_LIBRARY_AS_DATAFILE)
#define SIZE_FLAGS (DLL_FLAGS | 0)

void load_resource_library(void)
{
    HMODULE h = LoadLibraryExW(L"resources.dll", NULL, DLL_FLAGS);  /* VIOLATION */
    (void)h;
}
