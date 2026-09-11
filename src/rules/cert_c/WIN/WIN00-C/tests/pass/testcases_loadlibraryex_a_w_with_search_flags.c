/*
 * Rule: WIN00-C
 * Source: custom
 * Status: PASS - Should NOT trigger WIN00-C violation
 * Description: The A/W entry points of LoadLibraryEx are as specific as the
 * macro when their flags control the search path -- any
 * LOAD_LIBRARY_SEARCH_* flag, or LOAD_WITH_ALTERED_SEARCH_PATH with a fully
 * qualified path. A flags argument the rule cannot read (a variable) is
 * left alone rather than guessed at.
 */

#include <windows.h>

HMODULE load_from_app_dir(void) {
    return LoadLibraryExA("plugin.dll", NULL,
                          LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
}

HMODULE load_from_system32(void) {
    return LoadLibraryExW(L"fmifs.dll", NULL, (LOAD_LIBRARY_SEARCH_SYSTEM32));
}

HMODULE load_fully_qualified(const wchar_t *full_path) {
    return LoadLibraryExW(full_path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
}

HMODULE load_with_configured_flags(const char *name, DWORD flags) {
    return LoadLibraryExA(name, NULL, flags);
}
