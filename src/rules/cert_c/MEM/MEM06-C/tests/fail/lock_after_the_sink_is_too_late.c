/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: The block is locked only after the password has been used: the secret sat in pageable memory before the lock.
 */

#include <windows.h>
#include <stdlib.h>
#include <string.h>

void login(const char *typed) {
    HANDLE token;
    char *password = (char *)malloc(100);
    if (password == NULL) exit(1);
    strcpy(password, typed);
    LogonUserA("User", "Domain", password, LOGON32_LOGON_NETWORK,
               LOGON32_PROVIDER_DEFAULT, &token);
    VirtualLock(password, 100);
    free(password);
}
