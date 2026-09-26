/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: The password is copied into the block before VirtualLock: the pages it was written to were pageable when the secret landed in them.
 */

#include <windows.h>
#include <stdlib.h>
#include <string.h>

void login(const char *typed) {
    HANDLE token;
    char *password = (char *)malloc(100);
    if (password == NULL) exit(1);
    strcpy(password, typed);
    if (!VirtualLock(password, 100)) exit(1);
    LogonUserA("User", "Domain", password, LOGON32_LOGON_NETWORK,
               LOGON32_PROVIDER_DEFAULT, &token);
    free(password);
}
