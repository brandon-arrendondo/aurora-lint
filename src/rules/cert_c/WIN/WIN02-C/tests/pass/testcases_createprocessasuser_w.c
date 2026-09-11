/*
 * Rule: WIN02-C
 * Source: custom
 * Status: PASS - Should NOT trigger WIN02-C violation
 * Description: CreateProcessAsUserW is the compliant form -- the child's
 * token is explicit -- and must not be swept up by the widening to the
 * CreateProcessA/W entry points: the name continues past the `W`.
 */

#include <windows.h>

int run_as(HANDLE token, wchar_t *cmd) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    return CreateProcessAsUserW(token, NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) ? 0 : 1;
}
