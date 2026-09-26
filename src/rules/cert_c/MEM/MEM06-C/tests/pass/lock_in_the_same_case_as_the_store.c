/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: Juliet CWE-591 variant 15 shape: the allocation, lock and store sit in one switch case; the lock runs before the store on every path through that case.
 */

#include <windows.h>
#include <stdlib.h>
#include <string.h>

void login(int mode, const char *typed) {
    HANDLE token;
    char *password = "";
    switch (mode) {
    case 6:
        break;
    default:
        password = (char *)malloc(100);
        if (password == NULL) exit(1);
        if (!VirtualLock(password, 100)) exit(1);
        strcpy(password, typed);
        break;
    }
    LogonUserA("User", "Domain", password, LOGON32_LOGON_NETWORK,
               LOGON32_PROVIDER_DEFAULT, &token);
    free(password);
}
