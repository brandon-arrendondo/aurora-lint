/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: Juliet CWE-591 good shape: the block is VirtualLock'd before the password is stored and used.
 */

#include <windows.h>
#include <stdlib.h>
#include <string.h>

void login(const char *typed) {
    HANDLE token;
    char *password = (char *)malloc(100);
    if (password == NULL) exit(1);
    if (!VirtualLock(password, 100)) exit(1);
    strcpy(password, typed);
    if (LogonUserA("User", "Domain", password, LOGON32_LOGON_NETWORK,
                   LOGON32_PROVIDER_DEFAULT, &token) != 0) {
        CloseHandle(token);
    }
    free(password);
}
