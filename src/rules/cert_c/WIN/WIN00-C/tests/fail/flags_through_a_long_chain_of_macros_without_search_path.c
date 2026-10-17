/*
 * Rule: WIN00-C
 * Status: FAIL - Should trigger WIN00-C violation
 *
 * DLL_FLAGS reaches LOAD_LIBRARY_AS_DATAFILE through eight flags
 * expressions, each built from the next, so the value has no search-path
 * control bit however deep the chain is.
 */

#include <windows.h>

#define DLL_FLAGS (FLAGS_1 | 0)
#define FLAGS_1 (FLAGS_2 | 0)
#define FLAGS_2 (FLAGS_3 | 0)
#define FLAGS_3 (FLAGS_4 | 0)
#define FLAGS_4 (FLAGS_5 | 0)
#define FLAGS_5 (FLAGS_6 | 0)
#define FLAGS_6 (FLAGS_7 | 0)
#define FLAGS_7 (LOAD_LIBRARY_AS_DATAFILE | 0)

void load_resource_library(void)
{
    HMODULE h = LoadLibraryExW(L"resources.dll", NULL, DLL_FLAGS);  /* VIOLATION */
    (void)h;
}
