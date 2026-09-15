/*
 * Rule: WIN00-C
 * Source: custom
 * Status: FAIL - Should trigger WIN00-C violation
 * Description: `LoadLibrary` is a <windows.h> macro over LoadLibraryA and
 * LoadLibraryW, and real Win32 C names the entry point directly at least as
 * often as the macro -- every LoadLibrary in Ventoy2Disk is an A or W call
 * (DiskService.c:302, AlertSuppress.c:178). The rule matched the bare macro
 * name only, so the codebase chosen for having the textbook shape produced
 * zero findings. LoadLibraryEx with flags that say nothing about the search
 * path (0, or flags unrelated to it) searches exactly as LoadLibrary does.
 */

#include <windows.h>

static HMODULE g_fmifs;

void load_fmifs(void) {
    g_fmifs = LoadLibraryA("fmifs.dll");
}

HMODULE load_by_wide_name(const wchar_t *name) {
    return LoadLibraryW(name);
}

HMODULE load_ex_without_search_flags(void) {
    HMODULE h = LoadLibraryExA("plugin.dll", NULL, 0);
    if (h == NULL) {
        h = LoadLibraryExW(L"plugin.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    }
    return h;
}
