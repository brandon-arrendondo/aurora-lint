/*
 * Rule: WIN00-C
 * Status: PASS - Should NOT trigger WIN00-C violation
 *
 * DLL_FLAGS reaches LOAD_LIBRARY_SEARCH_SYSTEM32 through eight flags
 * expressions, each built from the next, so the call restricts the DLL
 * search to System32 however deep the chain is.
 */

#include <windows.h>

#define DLL_FLAGS (FLAGS_1 | LOAD_LIBRARY_AS_DATAFILE)
#define FLAGS_1 (FLAGS_2 | 0)
#define FLAGS_2 (FLAGS_3 | 0)
#define FLAGS_3 (FLAGS_4 | 0)
#define FLAGS_4 (FLAGS_5 | 0)
#define FLAGS_5 (FLAGS_6 | 0)
#define FLAGS_6 (FLAGS_7 | 0)
#define FLAGS_7 (LOAD_LIBRARY_SEARCH_SYSTEM32 | 0)

void load_resource_library(void)
{
    HMODULE h = LoadLibraryExW(L"resources.dll", NULL, DLL_FLAGS);
    (void)h;
}
