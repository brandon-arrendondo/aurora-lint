/*
 * Rule: WIN00-C
 * Status: FAIL - Should trigger WIN00-C violation
 *
 * DATA_FLAGS_ALL is not defined, but the constant evaluator reads its
 * trailing LL as an integer suffix and looks it up as DATA_FLAGS_A, which
 * is LOAD_LIBRARY_AS_DATAFILE with no search-path flag. ZZ sorts after
 * DATA_FLAGS_A, and its value must not depend on that order.
 */

#include <windows.h>

#define ZZ (DATA_FLAGS_ALL | 0)
#define DATA_FLAGS_A (LOAD_LIBRARY_AS_DATAFILE | 0)

void load_resource_library(void)
{
    HMODULE h = LoadLibraryExW(L"resources.dll", NULL, ZZ);  /* VIOLATION */
    (void)h;
}
