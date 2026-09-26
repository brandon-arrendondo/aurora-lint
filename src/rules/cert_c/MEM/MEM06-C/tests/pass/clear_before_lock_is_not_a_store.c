/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: Zeroing the fresh block before locking it stores no secret; the password is copied in only after VirtualLock.
 */

#include <windows.h>
#include <stdlib.h>
#include <string.h>

void login(const char *typed) {
    HANDLE token;
    char *password = (char *)malloc(100);
    if (password == NULL) exit(1);
    memset(password, 0, 100);
    if (!VirtualLock(password, 100)) exit(1);
    strcpy(password, typed);
    LogonUserA("User", "Domain", password, LOGON32_LOGON_NETWORK,
               LOGON32_PROVIDER_DEFAULT, &token);
    SecureZeroMemory(password, 100);
    free(password);
}
