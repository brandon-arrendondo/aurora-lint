/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: Juliet CWE-591 variant 18 shape: control reaches the allocation, lock and store through gotos; the CFG shows the lock on every path to the store.
 */

#include <windows.h>
#include <stdlib.h>
#include <string.h>

void login(const char *typed) {
    HANDLE token;
    char *password = "";
    goto source;
source:
    password = (char *)malloc(100);
    if (password == NULL) exit(1);
    if (!VirtualLock(password, 100)) exit(1);
    strcpy(password, typed);
    goto sink;
sink:
    LogonUserA("User", "Domain", password, LOGON32_LOGON_NETWORK,
               LOGON32_PROVIDER_DEFAULT, &token);
    free(password);
}
