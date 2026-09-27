/*
 * Rule: MEM06-C
 * Source: aurora-lint
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: ReadFile writes the password into its second argument before VirtualLock runs, so the lock comes too late.
 */

#include <windows.h>
#include <stdlib.h>

void login(HANDLE in) {
    DWORD got = 0;
    char *password = (char *)malloc(100);
    HANDLE token;
    if (password == NULL) {
        return;
    }
    if (!ReadFile(in, password, 99, &got, NULL)) {
        free(password);
        return;
    }
    VirtualLock(password, 100);
    password[got] = '\0';
    if (LogonUserA("User", "Domain", password, LOGON32_LOGON_NETWORK,
                   LOGON32_PROVIDER_DEFAULT, &token)) {
        CloseHandle(token);
    }
    free(password);
}
