/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: Juliet CWE-591 variant 12 shape: one branch locks the block, the other does not. The unlocked branch is a violation.
 */

#include <windows.h>
#include <stdlib.h>
#include <string.h>

int choose(void);

void login(void) {
    HANDLE token;
    char *password;
    if (choose()) {
        password = (char *)malloc(100);
        if (password == NULL) exit(1);
        strcpy(password, "typed");
    } else {
        password = (char *)malloc(100);
        if (password == NULL) exit(1);
        if (!VirtualLock(password, 100)) exit(1);
        strcpy(password, "typed");
    }
    if (LogonUserA("User", "Domain", password, LOGON32_LOGON_NETWORK,
                   LOGON32_PROVIDER_DEFAULT, &token) != 0) {
        CloseHandle(token);
    }
    free(password);
}
