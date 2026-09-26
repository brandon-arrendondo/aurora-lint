/*
 * Rule: MEM06-C
 * Source: testcases
 * Status: FAIL - Should trigger MEM06-C violation
 * Description: A heap-held password set as the PAM_AUTHTOK item is a credential; the block is never locked.
 */

#include <security/pam_appl.h>
#include <stdlib.h>
#include <string.h>

int set_token(pam_handle_t *pamh, const char *typed) {
    char *tok = strdup(typed);
    int rc;
    if (tok == NULL) return PAM_BUF_ERR;
    rc = pam_set_item(pamh, PAM_AUTHTOK, tok);
    free(tok);
    return rc;
}
