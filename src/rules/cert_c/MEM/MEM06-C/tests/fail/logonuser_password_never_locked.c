/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: Juliet CWE-591 shape: a malloc'd password reaches LogonUserA and is freed; the pages are never locked. Reported at the free.
 */

#include <windows.h>
#include <stdlib.h>
#include <string.h>

void login(const char *typed) {
    HANDLE token;
    char *password = (char *)malloc(100);
    if (password == NULL) {
        exit(1);
    }
    strcpy(password, typed);
    if (LogonUserA("User", "Domain", password, LOGON32_LOGON_NETWORK,
                   LOGON32_PROVIDER_DEFAULT, &token) != 0) {
        CloseHandle(token);
    }
    free(password);
}
