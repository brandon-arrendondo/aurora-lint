/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM06-C violation
 * Description: pam_set_item's item is a credential only for PAM_AUTHTOK/PAM_OLDAUTHTOK; a user name is not.
 */

#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>

int set_user(pam_handle_t *pamh, const char *typed) {
    char *user = strdup(typed);
    int rc;
    if (user == NULL) return PAM_BUF_ERR;
    rc = pam_set_item(pamh, PAM_USER, user);
    free(user);
    return rc;
}
