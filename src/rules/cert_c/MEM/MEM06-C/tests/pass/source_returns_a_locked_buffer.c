/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: Juliet CWE-591 variant 42/61 good shape: the source function locks the block before returning it.
 */

#include <windows.h>
#include <stdlib.h>
#include <string.h>

static char *read_password(void) {
    char *password = (char *)malloc(100);
    if (password == NULL) exit(1);
    if (!VirtualLock(password, 100)) exit(1);
    strcpy(password, "typed");
    return password;
}

void login(void) {
    HANDLE token;
    char *password = read_password();
    LogonUserA("User", "Domain", password, LOGON32_LOGON_NETWORK,
               LOGON32_PROVIDER_DEFAULT, &token);
    free(password);
}
