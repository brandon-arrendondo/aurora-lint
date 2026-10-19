/*
 * Rule: WIN00-C
 * Status: PASS - Should NOT trigger WIN00-C violation
 *
 * FLAGS_A and FLAGS_B are each defined in terms of the other, so neither
 * has a value, and a flags argument with no known value may carry a
 * search-path flag.
 */

#include <windows.h>

#define FLAGS_A (FLAGS_B | LOAD_LIBRARY_AS_DATAFILE)
#define FLAGS_B (FLAGS_A | 0)

void load_resource_library(void)
{
    HMODULE h = LoadLibraryExW(L"resources.dll", NULL, FLAGS_A);
    (void)h;
}
