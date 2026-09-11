/*
 * Rule: WIN02-C
 * Source: custom
 * Status: FAIL - Should trigger WIN02-C violation
 * Description: `CreateProcess` is a <windows.h> macro over CreateProcessA and
 * CreateProcessW. Ventoy2Disk spawns diskpart through CreateProcessA(NULL,
 * CmdBuf, NULL, NULL, FALSE, 0, ...) at four sites and the rule, matching
 * the bare macro name only, saw none of them.
 */

#include <windows.h>

int run_diskpart(char *cmd) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        return 1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    return 0;
}

int run_wide(wchar_t *cmd) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    return CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) ? 0 : 1;
}
